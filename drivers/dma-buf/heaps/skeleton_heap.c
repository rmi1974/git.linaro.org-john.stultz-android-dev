// SPDX-License-Identifier: GPL-2.0
/*
 * Skeleton DMA-Heap userspace exporter
 *
 * Copyright (C) 2020 Linaro Ltd.
 *
 * Based off of Andrew Davis' SRAM heap:
 * Copyright (C) 2019 Texas Instruments Incorporated - http://www.ti.com/
 *	Andrew F. Davis <afd@ti.com>
 */
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>


struct my_dma_heap {
	struct dma_heap *heap;
};

struct my_dma_heap_buffer {
	struct list_head attachments;
	struct mutex attachments_lock;
	unsigned long len;
	struct sg_table *sg_table;
	void *vaddr;
};

struct dma_heap_attachment {
	struct device *dev;
	struct sg_table *table;
	struct list_head list;
};

static struct sg_table *dup_sg_table(struct sg_table *table)
{
	struct sg_table *new_table;
	int ret, i;
	struct scatterlist *sg, *new_sg;

	new_table = kzalloc(sizeof(*new_table), GFP_KERNEL);
	if (!new_table)
		return ERR_PTR(-ENOMEM);

	ret = sg_alloc_table(new_table, table->nents, GFP_KERNEL);
	if (ret) {
		kfree(new_table);
		return ERR_PTR(-ENOMEM);
	}

	new_sg = new_table->sgl;
	for_each_sg(table->sgl, sg, table->nents, i) {
		memcpy(new_sg, sg, sizeof(*sg));
		new_sg->dma_address = 0;
		new_sg = sg_next(new_sg);
	}

	return new_table;
}

static int dma_heap_attach(struct dma_buf *dmabuf,
			   struct dma_buf_attachment *attachment)
{
	struct my_dma_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;
	struct sg_table *table;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	table = dup_sg_table(buffer->sg_table);
	if (IS_ERR(table)) {
		kfree(a);
		return -ENOMEM;
	}

	a->table = table;
	a->dev = attachment->dev;
	INIT_LIST_HEAD(&a->list);

	attachment->priv = a;

	mutex_lock(&buffer->attachments_lock);
	list_add(&a->list, &buffer->attachments);
	mutex_unlock(&buffer->attachments_lock);

	return 0;
}

static void dma_heap_detatch(struct dma_buf *dmabuf,
			     struct dma_buf_attachment *attachment)
{
	struct my_dma_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a = attachment->priv;

	mutex_lock(&buffer->attachments_lock);
	list_del(&a->list);
	mutex_unlock(&buffer->attachments_lock);

	sg_free_table(a->table);
	kfree(a->table);
	kfree(a);
}

static struct sg_table *dma_heap_map_dma_buf(struct dma_buf_attachment *attachment,
					     enum dma_data_direction direction)
{
	struct dma_heap_attachment *a = attachment->priv;
	struct sg_table *table = a->table;

	if (!dma_map_sg(attachment->dev, table->sgl, table->nents,
			direction))
		table = ERR_PTR(-ENOMEM);
	return table;
}

static void dma_heap_unmap_dma_buf(struct dma_buf_attachment *attachment,
				   struct sg_table *table,
				   enum dma_data_direction direction)
{
	dma_unmap_sg(attachment->dev, table->sgl, table->nents, direction);
}

static int dma_heap_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
					     enum dma_data_direction direction)
{
	struct my_dma_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;
	int ret = 0;

	mutex_lock(&buffer->attachments_lock);
	list_for_each_entry(a, &buffer->attachments, list) {
		dma_sync_sg_for_cpu(a->dev, a->table->sgl, a->table->nents,
				    direction);
	}
	mutex_unlock(&buffer->attachments_lock);

	return ret;
}

static int dma_heap_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
					   enum dma_data_direction direction)
{
	struct my_dma_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;

	mutex_lock(&buffer->attachments_lock);
	list_for_each_entry(a, &buffer->attachments, list) {
		dma_sync_sg_for_device(a->dev, a->table->sgl, a->table->nents,
				       direction);
	}
	mutex_unlock(&buffer->attachments_lock);

	return 0;
}

static int dma_heap_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct my_dma_heap_buffer *buffer = dmabuf->priv;
	int ret = -EINVAL;

	/* Handle mmap here */

	return ret;
}

static void *dma_heap_vmap(struct dma_buf *dmabuf)
{
	struct my_dma_heap_buffer *buffer = dmabuf->priv;

	/* Handle vmap here */

	return buffer->vaddr;
}

static void dma_heap_vunmap(struct dma_buf *dmabuf, void *vaddr)
{
	struct my_dma_heap_buffer *buffer = dmabuf->priv;

	/* Handle vunmap here */

}

static void dma_heap_dma_buf_release(struct dma_buf *dmabuf)
{
	struct my_dma_heap_buffer *buffer = dmabuf->priv;

	/* Free custom structure data here*/

	kfree(buffer);
}

const struct dma_buf_ops my_dma_heap_buf_ops = {
	.attach = dma_heap_attach,
	.detach = dma_heap_detatch,
	.map_dma_buf = dma_heap_map_dma_buf,
	.unmap_dma_buf = dma_heap_unmap_dma_buf,
        .begin_cpu_access = dma_heap_dma_buf_begin_cpu_access,
        .end_cpu_access = dma_heap_dma_buf_end_cpu_access,
	.mmap = dma_heap_mmap,
	.vmap = dma_heap_vmap,
	.vunmap = dma_heap_vunmap,
	.release = dma_heap_dma_buf_release,
};

static int my_dma_heap_allocate(struct dma_heap *heap,
				  unsigned long len,
				  unsigned long fd_flags,
				  unsigned long heap_flags)
{
	struct my_dma_heap *my_dma_heap = dma_heap_get_drvdata(heap);
	struct my_dma_heap_buffer *buffer;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct dma_buf *dmabuf;
	int ret;

	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	INIT_LIST_HEAD(&buffer->attachments);
	mutex_init(&buffer->attachments_lock);
	buffer->len = len;

	/* Alloc / Initalize custom buffer structure data here */

	/* Fill in buffer->sg_table here */

	/* create the dmabuf */
	exp_info.ops = &my_dma_heap_buf_ops;
	exp_info.size = buffer->len;
	exp_info.flags = fd_flags;
	exp_info.priv = buffer;
	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto free_other;
	}

	ret = dma_buf_fd(dmabuf, fd_flags);
	if (ret < 0) {
		dma_buf_put(dmabuf);
		/* just return, as put will call release and that will free */
		return ret;
	}

	return ret;

free_other:
	/*Free custom buffer structure data here */
free_buffer:
	kfree(buffer);

	return ret;
}

static struct dma_heap_ops my_dma_heap_ops = {
	.allocate = my_dma_heap_allocate,
};

static int my_dma_heap_create(void)
{
	struct my_dma_heap *my_dma_heap;
	struct dma_heap_export_info exp_info;


	my_dma_heap = kzalloc(sizeof(*my_dma_heap), GFP_KERNEL);
	if (!my_dma_heap)
		return -ENOMEM;

	/* Initialize any custom my_dma_heap structure values here */

	exp_info.name = "myheap";
	exp_info.ops = &my_dma_heap_ops;
	exp_info.priv = my_dma_heap;
	my_dma_heap->heap = dma_heap_add(&exp_info);
	if (IS_ERR(my_dma_heap->heap)) {
		int ret = PTR_ERR(my_dma_heap->heap);
		kfree(my_dma_heap);
		return ret;
	}

	return 0;
}
device_initcall(my_dma_heap_create);

