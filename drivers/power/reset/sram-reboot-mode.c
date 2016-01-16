/*
 * Copyright (c) 2016, Linaro Limited
 * Based on syscon-reboot-mode.c
 * Copyright (c) 2016, Fuzhou Rockchip Electronics Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/reboot.h>
#include <linux/regmap.h>
#include "reboot-mode.h"

static void __iomem *reboot_reason_val_addr;

static int sram_reboot_mode_write(int magic)
{
	writel(magic, reboot_reason_val_addr);
	return 0;
}

static int sram_reboot_mode_probe(struct platform_device *pdev)
{
	struct resource *res;
	int ret;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return PTR_ERR(res);

	reboot_reason_val_addr = devm_ioremap(&pdev->dev, res->start, resource_size(res));
	if (IS_ERR(reboot_reason_val_addr))
		return PTR_ERR(reboot_reason_val_addr);

	ret = reboot_mode_register(&pdev->dev, sram_reboot_mode_write);
	if (ret)
		dev_err(&pdev->dev, "can't register reboot mode\n");

	return ret;
}

static const struct of_device_id sram_reboot_mode_of_match[] = {
	{ .compatible = "sram-reboot-mode" },
	{}
};

static struct platform_driver sram_reboot_mode_driver = {
	.probe = sram_reboot_mode_probe,
	.driver = {
		.name = "sram-reboot-mode",
		.of_match_table = sram_reboot_mode_of_match,
	},
};
module_platform_driver(sram_reboot_mode_driver);

MODULE_AUTHOR("John Stultz <john.stultz@linaro.org>");
MODULE_DESCRIPTION("SRAM reboot mode driver");
MODULE_LICENSE("GPL v2");
