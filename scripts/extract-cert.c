/* Extract X.509 certificate in DER form from PKCS#11 or PEM.
 *
 * Copyright © 2014-2015 Red Hat, Inc. All Rights Reserved.
 * Copyright © 2015      Intel Corporation.
 *
 * Authors: David Howells <dhowells@redhat.com>
 *          David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the licence, or (at your option) any later version.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#else
#include <openssl/engine.h>
#endif

#define PKEY_ID_PKCS7 2

static __attribute__((noreturn))
void format(void)
{
	fprintf(stderr,
		"Usage: scripts/extract-cert <source> <dest>\n");
	exit(2);
}

static void display_openssl_errors(int l)
{
	const char *file;
	char buf[120];
	unsigned long e;
	int line;

	if (ERR_peek_error() == 0)
		return;
	fprintf(stderr, "At main.c:%d:\n", l);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	while ((e = ERR_get_error_all(&file, &line, NULL, NULL, NULL))) {
#else
	while ((e = ERR_get_error_line(&file, &line))) {
#endif
		ERR_error_string(e, buf);
		fprintf(stderr, "- SSL %s: %s:%d\n", buf, file, line);
	}
}

#define ERR(cond, fmt, ...)				\
	do {						\
		bool __cond = (cond);			\
		display_openssl_errors(__LINE__);	\
		if (__cond) {				\
			err(1, fmt, ## __VA_ARGS__);	\
		}					\
	} while(0)

static const char *key_pass;
static BIO *wb;
static char *cert_dst;
int kbuild_verbose;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int read_pkcs11_pin(char *buf, int size, int rwflag, void *data)
{
	const char *pin = data;
	size_t len;

	if (!pin || size <= 0)
		return -1;
	len = strlen(pin);
	if (len >= (size_t)size)
		return -1;
	memcpy(buf, pin, len + 1);
	return len;
}

static X509 *load_cert_pkcs11(const char *uri)
{
	OSSL_PROVIDER *provider, *default_provider;
	OSSL_STORE_CTX *store;
	UI_METHOD *ui;
	X509 *cert = NULL;

	provider = OSSL_PROVIDER_try_load(NULL, "pkcs11", 1);
	ERR(!provider, "Load PKCS#11 provider");
	default_provider = OSSL_PROVIDER_try_load(NULL, "default", 1);
	ERR(!default_provider, "Load default provider");
	ui = UI_UTIL_wrap_read_pem_callback(read_pkcs11_pin, 0);
	ERR(!ui, "Create PKCS#11 PIN callback");
	store = OSSL_STORE_open(uri, ui, (void *)key_pass, NULL, NULL);
	ERR(!store, "Open PKCS#11 certificate");
	while (!OSSL_STORE_eof(store)) {
		OSSL_STORE_INFO *info = OSSL_STORE_load(store);

		if (!info) {
			ERR(OSSL_STORE_error(store), "Load PKCS#11 certificate");
			break;
		}
		if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_CERT)
			cert = OSSL_STORE_INFO_get1_CERT(info);
		OSSL_STORE_INFO_free(info);
		if (cert)
			break;
	}
	ERR(!OSSL_STORE_close(store), "Close PKCS#11 certificate store");
	UI_destroy_method(ui);
	OSSL_PROVIDER_unload(default_provider);
	OSSL_PROVIDER_unload(provider);
	ERR(!cert, "Get X.509 from PKCS#11");
	return cert;
}
#endif

static void write_cert(X509 *x509)
{
	char buf[200];

	if (!wb) {
		wb = BIO_new_file(cert_dst, "wb");
		ERR(!wb, "%s", cert_dst);
	}
	X509_NAME_oneline(X509_get_subject_name(x509), buf, sizeof(buf));
	ERR(!i2d_X509_bio(wb, x509), "%s", cert_dst);
	if (kbuild_verbose)
		fprintf(stderr, "Extracted cert: %s\n", buf);
}

int main(int argc, char **argv)
{
	char *cert_src;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ERR_clear_error();

	kbuild_verbose = atoi(getenv("KBUILD_VERBOSE")?:"0");

        key_pass = getenv("KBUILD_SIGN_PIN");

	if (argc != 3)
		format();

	cert_src = argv[1];
	cert_dst = argv[2];

	if (!cert_src[0]) {
		/* Invoked with no input; create empty file */
		FILE *f = fopen(cert_dst, "wb");
		ERR(!f, "%s", cert_dst);
		fclose(f);
		exit(0);
	} else if (!strncmp(cert_src, "pkcs11:", 7)) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		X509 *cert = load_cert_pkcs11(cert_src);

		write_cert(cert);
		X509_free(cert);
#else
		ENGINE *e;
		struct {
			const char *cert_id;
			X509 *cert;
		} parms;

		parms.cert_id = cert_src;
		parms.cert = NULL;

		ENGINE_load_builtin_engines();
		ERR_clear_error();
		e = ENGINE_by_id("pkcs11");
		ERR(!e, "Load PKCS#11 ENGINE");
		if (ENGINE_init(e))
			ERR_clear_error();
		else
			ERR(1, "ENGINE_init");
		if (key_pass)
			ERR(!ENGINE_ctrl_cmd_string(e, "PIN", key_pass, 0), "Set PKCS#11 PIN");
		ENGINE_ctrl_cmd(e, "LOAD_CERT_CTRL", 0, &parms, NULL, 1);
		ERR(!parms.cert, "Get X.509 from PKCS#11");
		write_cert(parms.cert);
#endif
	} else {
		BIO *b;
		X509 *x509;

		b = BIO_new_file(cert_src, "rb");
		ERR(!b, "%s", cert_src);

		while (1) {
			x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);
			if (wb && !x509) {
				unsigned long err = ERR_peek_last_error();
				if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
				    ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
					ERR_clear_error();
					break;
				}
			}
			ERR(!x509, "%s", cert_src);
			write_cert(x509);
		}
	}

	BIO_free(wb);

	return 0;
}
