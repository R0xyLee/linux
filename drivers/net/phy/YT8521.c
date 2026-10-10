// SPDX-License-Identifier: GPL-2.0+
/*
 * drivers/net/phy/at803x.c
 *
 * Driver for Atheros 803x PHY
 *
 * Author: Matus Ujhelyi <ujhelyi.m@gmail.com>
 */

#include <linux/phy.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/of_gpio.h>
#include <linux/gpio/consumer.h>


#define YT8521_PHY_ID 0x0000011a
#define YT8521_PHY_ID_MASK			0x00000fff

#define YT8521_EXT_ADDR_REG	0x1e
#define YT8521_EXT_DATA_REG	0x1f
#define YT8521_CHIP_CONFIG_REG	0xa001
#define YT8521_RXC_DLY_EN		BIT(8)


MODULE_DESCRIPTION("YT8521 PHY driver");
MODULE_AUTHOR("machao");
MODULE_LICENSE("GPL");

struct yt8521_priv {
	bool phy_reset:1;
	u32 quirks;
};

static int yt8521_probe(struct phy_device *phydev)
{
	struct device *dev = &phydev->mdio.dev;
	struct yt8521_priv *priv;
	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	phydev->priv = priv;
	phy_write(phydev,0x4,0x11e1);
	phy_write(phydev,0x0,0x1000);
	phy_write(phydev,0x1e,0xa00d);
	phy_write(phydev,0x1f,0x660);
	phy_write(phydev,0x1e,0xa00e);
	phy_write(phydev,0x1f,0x40);
	phy_write(phydev,0x1e,0xa003);
	phy_write(phydev,0x1f,0xfd);

	return 0;
}


static int yt8521_config_init(struct phy_device *phydev)
{
	int ret;

	/* The fixed 0x00fd RGMII timing below needs the 1.9 ns base RX delay.
	 * Mainline U-Boot can disable it and use the fine delay in 0xa003
	 * instead. Restore it before overwriting that register, or RX has
	 * no delay after the bootloader hands over the PHY.
	 */
	mutex_lock(&phydev->mdio.bus->mdio_lock);
	ret = __phy_write(phydev, YT8521_EXT_ADDR_REG, YT8521_CHIP_CONFIG_REG);
	if (!ret)
		ret = __phy_set_bits(phydev, YT8521_EXT_DATA_REG,
				     YT8521_RXC_DLY_EN);
	mutex_unlock(&phydev->mdio.bus->mdio_lock);
	if (ret < 0)
		return ret;

	phy_write(phydev,0x4,0x11e1);
	phy_write(phydev,0x0,0x1000);
	phy_write(phydev,0x1e,0xa00d);
	phy_write(phydev,0x1f,0x660);
	phy_write(phydev,0x1e,0xa00e);
	phy_write(phydev,0x1f,0x40);
	phy_write(phydev,0x1e,0xa003);
	phy_write(phydev,0x1f,0xfd);
	return 0;
}

static struct phy_driver yt8521_driver[] = {
      	{
	.phy_id		= YT8521_PHY_ID,
	.name		= "YT8521 ethernet",
	.phy_id_mask	= YT8521_PHY_ID_MASK,
	.probe		= yt8521_probe,
	.config_init	= yt8521_config_init,
	.soft_reset     = genphy_no_soft_reset,
	.get_features   = genphy_read_abilities,
	.aneg_done      = genphy_aneg_done,
	.suspend        = genphy_suspend,
	.resume         = genphy_resume,
	.set_loopback   = genphy_loopback,
} };

module_phy_driver(yt8521_driver);

static struct mdio_device_id __maybe_unused atheros_tbl[] = {
	{ YT8521_PHY_ID, YT8521_PHY_ID_MASK },
	{ }
};

MODULE_DEVICE_TABLE(mdio, atheros_tbl);
