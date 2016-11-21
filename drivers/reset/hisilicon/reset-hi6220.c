/*
 * Copyright (c) 2016-2017 Linaro Ltd.
 * Copyright (c) 2016-2017 HiSilicon Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <dt-bindings/reset/hisi,hi6220-resets.h>

#include "reset.h"

static const struct hisi_reset_channel_data hi6220_media_rst[] = {
	[MEDIA_G3D] = HISI_RST_SEP(0x52c, 0),
	[MEDIA_CODEC_VPU] = HISI_RST_SEP(0x52c, 2),
	[MEDIA_CODEC_JPEG] = HISI_RST_SEP(0x52c, 3),
	[MEDIA_ISP] = HISI_RST_SEP(0x52c, 4),
	[MEDIA_ADE] = HISI_RST_SEP(0x52c, 5),
	[MEDIA_MMU] = HISI_RST_SEP(0x52c, 6),
	[MEDIA_XG2RAM1] = HISI_RST_SEP(0x52c, 7),
};

static struct hisi_reset_controller_data hi6220_media_controller = {
	.nr_channels = ARRAY_SIZE(hi6220_media_rst),
	.channels = hi6220_media_rst,
};

static const struct hisi_reset_channel_data hi6220_sysctrl_rst[] = {
	[PERIPH_RSTDIS0_MMC0] = HISI_RST_SEP(0x300, 0),
	[PERIPH_RSTDIS0_MMC1] = HISI_RST_SEP(0x300, 1),
	[PERIPH_RSTDIS0_MMC2] = HISI_RST_SEP(0x300, 2),
	[PERIPH_RSTDIS0_NANDC] = HISI_RST_SEP(0x300, 3),
	[PERIPH_RSTDIS0_USBOTG_BUS] = HISI_RST_SEP(0x300, 4),
	[PERIPH_RSTDIS0_POR_PICOPHY] = HISI_RST_SEP(0x300, 5),
	[PERIPH_RSTDIS0_USBOTG] = HISI_RST_SEP(0x300, 6),
	[PERIPH_RSTDIS0_USBOTG_32K] = HISI_RST_SEP(0x300, 7),
	[PERIPH_RSTDIS1_HIFI] = HISI_RST_SEP(0x310, 0),
	[PERIPH_RSTDIS1_DIGACODEC] = HISI_RST_SEP(0x310, 5),
	[PERIPH_RSTEN2_IPF] = HISI_RST_SEP(0x320, 0),
	[PERIPH_RSTEN2_SOCP] = HISI_RST_SEP(0x320, 1),
	[PERIPH_RSTEN2_DMAC] = HISI_RST_SEP(0x320, 2),
	[PERIPH_RSTEN2_SECENG] = HISI_RST_SEP(0x320, 3),
	[PERIPH_RSTEN2_ABB] = HISI_RST_SEP(0x320, 4),
	[PERIPH_RSTEN2_HPM0] = HISI_RST_SEP(0x320, 5),
	[PERIPH_RSTEN2_HPM1] = HISI_RST_SEP(0x320, 6),
	[PERIPH_RSTEN2_HPM2] = HISI_RST_SEP(0x320, 7),
	[PERIPH_RSTEN2_HPM3] = HISI_RST_SEP(0x320, 8),
	[PERIPH_RSTEN3_CSSYS] = HISI_RST_SEP(0x330, 0),
	[PERIPH_RSTEN3_I2C0] = HISI_RST_SEP(0x330, 1),
	[PERIPH_RSTEN3_I2C1] = HISI_RST_SEP(0x330, 2),
	[PERIPH_RSTEN3_I2C2] = HISI_RST_SEP(0x330, 3),
	[PERIPH_RSTEN3_I2C3] = HISI_RST_SEP(0x330, 4),
	[PERIPH_RSTEN3_UART1] = HISI_RST_SEP(0x330, 5),
	[PERIPH_RSTEN3_UART2] = HISI_RST_SEP(0x330, 6),
	[PERIPH_RSTEN3_UART3] = HISI_RST_SEP(0x330, 7),
	[PERIPH_RSTEN3_UART4] = HISI_RST_SEP(0x330, 8),
	[PERIPH_RSTEN3_SSP] = HISI_RST_SEP(0x330, 9),
	[PERIPH_RSTEN3_PWM] = HISI_RST_SEP(0x330, 10),
	[PERIPH_RSTEN3_BLPWM] = HISI_RST_SEP(0x330, 11),
	[PERIPH_RSTEN3_TSENSOR] = HISI_RST_SEP(0x330, 12),
	[PERIPH_RSTEN3_DAPB] = HISI_RST_SEP(0x330, 18),
	[PERIPH_RSTEN3_HKADC] = HISI_RST_SEP(0x330, 19),
	[PERIPH_RSTEN3_CODEC_SSI] = HISI_RST_SEP(0x330, 20),
	[PERIPH_RSTEN8_RS0] = HISI_RST_SEP(0x340, 0),
	[PERIPH_RSTEN8_RS2] = HISI_RST_SEP(0x340, 1),
	[PERIPH_RSTEN8_RS3] = HISI_RST_SEP(0x340, 2),
	[PERIPH_RSTEN8_MS0] = HISI_RST_SEP(0x340, 3),
	[PERIPH_RSTEN8_MS2] = HISI_RST_SEP(0x340, 5),
	[PERIPH_RSTEN8_XG2RAM0] = HISI_RST_SEP(0x340, 6),
	[PERIPH_RSTEN8_X2SRAM_TZMA] = HISI_RST_SEP(0x340, 7),
	[PERIPH_RSTEN8_SRAM] = HISI_RST_SEP(0x340, 8),
	[PERIPH_RSTEN8_HARQ] = HISI_RST_SEP(0x340, 10),
	[PERIPH_RSTEN8_DDRC] = HISI_RST_SEP(0x340, 12),
	[PERIPH_RSTEN8_DDRC_APB] = HISI_RST_SEP(0x340, 13),
	[PERIPH_RSTEN8_DDRPACK_APB] = HISI_RST_SEP(0x340, 14),
	[PERIPH_RSTEN8_DDRT] = HISI_RST_SEP(0x340, 17),
	[PERIPH_RSDIST9_CARM_DAP] = HISI_RST_SEP(0x350, 0),
	[PERIPH_RSDIST9_CARM_ATB] = HISI_RST_SEP(0x350, 1),
	[PERIPH_RSDIST9_CARM_LBUS] = HISI_RST_SEP(0x350, 2),
	[PERIPH_RSDIST9_CARM_POR] = HISI_RST_SEP(0x350, 3),
	[PERIPH_RSDIST9_CARM_CORE] = HISI_RST_SEP(0x350, 4),
	[PERIPH_RSDIST9_CARM_DBG] = HISI_RST_SEP(0x350, 5),
	[PERIPH_RSDIST9_CARM_L2] = HISI_RST_SEP(0x350, 6),
	[PERIPH_RSDIST9_CARM_SOCDBG] = HISI_RST_SEP(0x350, 7),
	[PERIPH_RSDIST9_CARM_ETM] = HISI_RST_SEP(0x350, 8),
};

static struct hisi_reset_controller_data hi6220_sysctrl_controller = {
	.nr_channels = ARRAY_SIZE(hi6220_sysctrl_rst),
	.channels = hi6220_sysctrl_rst,
};

static const struct of_device_id hi6220_reset_match[] = {
	{ .compatible = "hisilicon,hi6220-reset-sysctrl",
	  .data = &hi6220_sysctrl_controller, },
	{ .compatible = "hisilicon,hi6220-reset-mediactrl",
	  .data = &hi6220_media_controller, },
	{},
};
MODULE_DEVICE_TABLE(of, hi6220_reset_match);

static struct platform_driver hi6220_reset_driver = {
	.probe = hisi_reset_probe,
	.driver = {
		.name = "reset-hi6220",
		.of_match_table = hi6220_reset_match,
	},
};

static int __init hi6220_reset_init(void)
{
	return platform_driver_register(&hi6220_reset_driver);
}
arch_initcall(hi6220_reset_init);

MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:hi6220-reset");
MODULE_DESCRIPTION("HiSilicon hi6220 Reset Driver");
