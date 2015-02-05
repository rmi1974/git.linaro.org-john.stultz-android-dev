/*
 * HACK: For Hisilicon Hi3660 SoC, do ugly init things here
 *
 * Copyright (C) 2015 Hisilicon Ltd.
 * Author: Bintian Wang <bintian.wang@huawei.com>
 *
 */

#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/printk.h>

static void set_adv7533_pmic_reg(void)
{
	unsigned char data = 0;
	void __iomem *iomem = ioremap(0xfff34000, 0x1000);

	data = readb(iomem + (0x60 << 2)) | (1 << 1);
	writeb(data, iomem + (0x60 << 2));
	data = (readb(iomem + (0x61 << 2)) & ~(0xF)) | 2;
	writeb(data, iomem + (0x61 << 2));

	data = readb(iomem + (0x5C << 2)) | (1 << 1);
	writeb(data, iomem + (0x5C << 2));
	data = (readb(iomem + (0x5D << 2)) & ~(0xF)) | 9;
	writeb(data, iomem + (0x5D << 2));
	iounmap(iomem);
}

static int __init hi3660_sysconf(void)
{
        static void __iomem *base = NULL;

	set_adv7533_pmic_reg();

        return 0;
}
postcore_initcall(hi3660_sysconf);
