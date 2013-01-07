/*
 * KGDB FIQ entry
 *
 * Copyright 1996,1997,1998 Russell King.
 * Copyright 2012 Linaro Ltd.
 *		  Anton Vorontsov <anton.vorontsov@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/memory.h>
#include <asm/unwind.h>
#include "entry-header.S"

	.text

@ This is needed for usr_entry/alignment_trap
.LCcralign:
	.long	cr_alignment
.LCdohandle:
	.long	kgdb_fiq_do_handle

	.macro	fiq_handler
	ldr	r1, =.LCdohandle
	mov	r0, sp
	adr	lr, BSYM(9997f)
	ldr	pc, [r1]
9997:
	.endm

	.align	5
__fiq_svc:
	svc_entry
	fiq_handler
	mov	r0, sp
	ldmib	r0, {r1 - r14}
	msr	cpsr_c, #FIQ_MODE | PSR_I_BIT | PSR_F_BIT
	add	r8, r0, #S_PC
	ldr	r9, [r0, #S_PSR]
	msr	spsr_cxsf, r9
	ldr	r0, [r0, #S_R0]
	ldmia	r8, {pc}^

 UNWIND(.fnend		)
ENDPROC(__fiq_svc)
	.ltorg

	.align	5
__fiq_usr:
	usr_entry
	kuser_cmpxchg_check
	fiq_handler
	get_thread_info tsk
	mov	why, #0
	b	ret_to_user_from_irq
 UNWIND(.fnend		)
ENDPROC(__fiq_usr)
	.ltorg

	.global kgdb_fiq_handler
kgdb_fiq_handler:

	vector_stub	fiq, FIQ_MODE, 4

	.long	__fiq_usr			@  0  (USR_26 / USR_32)
	.long	__fiq_svc			@  1  (FIQ_26 / FIQ_32)
	.long	__fiq_svc			@  2  (IRQ_26 / IRQ_32)
	.long	__fiq_svc			@  3  (SVC_26 / SVC_32)
	.long	__fiq_svc			@  4
	.long	__fiq_svc			@  5
	.long	__fiq_svc			@  6
	.long	__fiq_svc			@  7
	.long	__fiq_svc			@  8
	.long	__fiq_svc			@  9
	.long	__fiq_svc			@  a
	.long	__fiq_svc			@  b
	.long	__fiq_svc			@  c
	.long	__fiq_svc			@  d
	.long	__fiq_svc			@  e
	.long	__fiq_svc			@  f

	.global kgdb_fiq_handler_end
kgdb_fiq_handler_end:
