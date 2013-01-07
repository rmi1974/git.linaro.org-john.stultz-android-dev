/*
 * KGDB FIQ
 *
 * Copyright 2010 Google, Inc.
 *		  Arve Hjønnevåg <arve@android.com>
 *		  Colin Cross <ccross@android.com>
 * Copyright 2012 Linaro Ltd.
 *		  Anton Vorontsov <anton.vorontsov@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/hardirq.h>
#include <linux/atomic.h>
#include <linux/kdb.h>
#include <linux/kgdb.h>
#include <asm/fiq.h>
#include <asm/exception.h>

static int kgdb_fiq_enabled;
module_param_named(enable, kgdb_fiq_enabled, int, 0600);
MODULE_PARM_DESC(enable, "set to 1 to enable FIQ KGDB");

static bool (*is_kgdb_fiq)(void);
static void (*kgdb_enable_fiq)(bool on);

asmlinkage void __exception_irq_entry kgdb_fiq_do_handle(struct pt_regs *regs)
{
	if (!is_kgdb_fiq())
		return;
	if (!kgdb_nmi_poll_knock())
		return;

	nmi_enter();
	kgdb_handle_exception(1, 0, 0, regs);
	nmi_exit();
}

static struct fiq_handler kgdb_fiq_desc = {
	.name = "kgdb",
};

static long kgdb_fiq_setup_stack(void *info)
{
	struct pt_regs regs;

	regs.ARM_sp = __get_free_pages(GFP_KERNEL, THREAD_SIZE_ORDER) +
			THREAD_START_SP;
	WARN_ON(!regs.ARM_sp);

	set_fiq_regs(&regs);
	return 0;
}

/**
 * kgdb_fiq_enable_nmi - Manage NMI-triggered entry to KGDB
 * @on: Flag to either enable or disable an NMI
 *
 * This function manages NMIs that usually cause KGDB to enter. That is, not
 * all NMIs should be enabled or disabled, but only those that issue
 * kgdb_handle_exception().
 *
 * The call counts disable requests, and thus allows to nest disables. But
 * trying to enable already enabled NMI is an error.
 */
static void kgdb_fiq_enable_nmi(bool on)
{
	static atomic_t cnt;
	int ret;

	ret = atomic_add_return(on ? 1 : -1, &cnt);
	if (ret > 1 && on) {
		/*
		 * There should be only one instance that calls this function
		 * in "enable, disable" order. All other users must call
		 * disable first, then enable. If not, something is wrong.
		 */
		WARN_ON(1);
		return;
	}

	kgdb_enable_fiq(ret > 0);
}

int __init kgdb_register_fiq(void (*mach_kgdb_enable_fiq)(bool on),
			     bool (*mach_is_kgdb_fiq)(void))
{
	int err;
	int cpu;

	if (!kgdb_fiq_enabled)
		return -ENODEV;

	kgdb_enable_fiq = mach_kgdb_enable_fiq;
	is_kgdb_fiq = mach_is_kgdb_fiq;

	err = claim_fiq(&kgdb_fiq_desc);
	if (err) {
		pr_warn("%s: unable to claim fiq", __func__);
		return err;
	}

	for_each_possible_cpu(cpu)
		work_on_cpu(cpu, kgdb_fiq_setup_stack, NULL);

	set_fiq_handler(&kgdb_fiq_handler,
			&kgdb_fiq_handler_end - &kgdb_fiq_handler);

	arch_kgdb_ops.enable_nmi = kgdb_fiq_enable_nmi;
	return 0;
}
