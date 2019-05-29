// SPDX-License-Identifier: GPL-2.0
/*
 * DMABUF System heap exporter
 *
 * Copyright (C) 2011 Google, Inc.
 * Copyright (C) 2019 Linaro Ltd.
 */

#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/dma-heap.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <asm/page.h>

#include "heap-helpers.h"

struct dma_heap *sys_heap;


#define NUM_ORDERS ARRAY_SIZE(orders)
#define HIGH_ORDER_GFP  (((GFP_HIGHUSER | __GFP_ZERO | __GFP_NOWARN \
				| __GFP_NORETRY) & ~__GFP_RECLAIM) \
				| __GFP_COMP)
#define LOW_ORDER_GFP (GFP_HIGHUSER | __GFP_ZERO | __GFP_COMP)
static gfp_t order_flags[] = {HIGH_ORDER_GFP, LOW_ORDER_GFP, LOW_ORDER_GFP};
static const unsigned int orders[] = {8, 4, 0};


static void system_heap_free(struct heap_helper_buffer *buffer)
{
	struct sg_table *table = buffer->sg_table;
	struct scatterlist *sg;
	int i;

	for_each_sg(table->sgl, sg, table->nents, i) {
		struct page *page = sg_page(sg);
		__free_pages(page, compound_order(page));
	}
	sg_free_table(table);
	kfree(table);
	kfree(buffer);
}

static struct page *alloc_largest_available(unsigned long size,
					    unsigned int max_order)
{
	struct page *page;
	int i;

	for (i = 0; i < NUM_ORDERS; i++) {
		if (size <  (PAGE_SIZE << orders[i]))
			continue;
		if (max_order < orders[i])
			continue;

		page = alloc_pages(order_flags[i], orders[i]);
		if (!page)
			continue;
		return page;
	}
	return NULL;
}


static int system_heap_allocate(struct dma_heap *heap,
				unsigned long len,
				unsigned long fd_flags,
				unsigned long heap_flags)
{
	struct heap_helper_buffer *helper_buffer;
	unsigned long size_remaining = len;
	unsigned int max_order = orders[0];
	struct dma_buf *dmabuf;
	struct sg_table *table;
	struct scatterlist *sg;
	struct list_head pages;
        struct page *page, *tmp_page;

	int ret = -ENOMEM;
	int i, j;

	helper_buffer = kzalloc(sizeof(*helper_buffer), GFP_KERNEL);
	if (!helper_buffer)
		return -ENOMEM;

	init_heap_helper_buffer(helper_buffer, system_heap_free);
	helper_buffer->heap = heap;
	helper_buffer->size = len;


	INIT_LIST_HEAD(&pages);
	i=0;
	while (size_remaining > 0) {
		/*
		 * Avoid trying to allocate memory if the process
		 * has been killed by by SIGKILL
		 */
		if (fatal_signal_pending(current))
			goto err0;

                page = alloc_largest_available(size_remaining, max_order);
                if (!page)
                        goto err0;
                list_add_tail(&page->lru, &pages);
                size_remaining -= PAGE_SIZE << compound_order(page);
                max_order = compound_order(page);
                i++;
        }

	table = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!table) {
		ret = -ENOMEM;
		goto err0;
	}

	ret = sg_alloc_table(table, i, GFP_KERNEL);
	if (ret)
		goto err1;

        sg = table->sgl;
        list_for_each_entry_safe(page, tmp_page, &pages, lru) {
                sg_set_page(sg, page, PAGE_SIZE << compound_order(page), 0);
                sg = sg_next(sg);
                list_del(&page->lru);
        }

	/* create the dmabuf */
	dmabuf = heap_helper_export_dmabuf(helper_buffer, fd_flags);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto err2;
	}

	helper_buffer->dmabuf = dmabuf;
	helper_buffer->sg_table = table;

	ret = dma_buf_fd(dmabuf, fd_flags);
	if (ret < 0) {
		dma_buf_put(dmabuf);
		/* just return, as put will call release and that will free */
		return ret;
	}

	return ret;

err2:
	for_each_sg(table->sgl, sg, i, j)
		__free_page(sg_page(sg));
	sg_free_table(table);
err1:
	kfree(table);
err0:
	list_for_each_entry_safe(page, tmp_page, &pages, lru)
		__free_pages(page, compound_order(page));
	kfree(helper_buffer);

	return ret;
}

static const struct dma_heap_ops system_heap_ops = {
	.allocate = system_heap_allocate,
};

static int system_heap_create(void)
{
	struct dma_heap_export_info exp_info;
	int ret = 0;

	exp_info.name = "system_heap";
	exp_info.ops = &system_heap_ops;
	exp_info.priv = NULL;

	sys_heap = dma_heap_add(&exp_info);
	if (IS_ERR(sys_heap))
		ret = PTR_ERR(sys_heap);

	return ret;
}
module_init(system_heap_create);
MODULE_LICENSE("GPL v2");
