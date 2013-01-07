/*
 * KGDB FIQ board support
 *
 * Copyright 2012 Linaro Ltd.
 *		  Anton Vorontsov <anton.vorontsov@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kgdb.h>
#include <mach/hardware.h>
#include <mach/platform.h>
#include <asm/hardware/vic.h>

static void *kgdb_irq_base;

static int kgdb_irq;
module_param_named(uart_num, kgdb_irq, int, 0600);
MODULE_PARM_DESC(uart_num, "UART<number> port to use for KGDB FIQ");

static void kgdb_fiq_select(bool on)
{
	void __iomem *sel = kgdb_irq_base + VIC_INT_SELECT;
	u32 msk = 1 << kgdb_irq;
	u32 val;

	pr_debug("rerouting VIC vector %d to %s\n", kgdb_irq,
		 on ? "FIQ" : "IRQ");

	val = readl(sel);
	val &= ~msk;
	if (on)
		val |= msk;
	writel(val, sel);
}

static bool kgdb_is_fiq_rised(void)
{
	return readl(kgdb_irq_base + VIC_FIQ_STATUS) & (1 << kgdb_irq);
}

static int __init kgdb_fiq_init(void)
{
	kgdb_irq_base = __io_address(VERSATILE_VIC_BASE);
	kgdb_irq += INT_UARTINT0;
	WARN_ON(kgdb_irq > INT_UARTINT2);

	return kgdb_register_fiq(kgdb_fiq_select, kgdb_is_fiq_rised);
}
console_initcall(kgdb_fiq_init);
