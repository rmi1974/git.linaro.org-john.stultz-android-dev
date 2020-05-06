// SPDX-License-Identifier: GPL-2.0
/*
 * Uncached DMA-Heap exporter
 *
 * Copyright (C) 2020 Linaro Ltd.
 *
 * Based off of Andrew Davis' SRAM heap:
 * Copyright (C) 2019 Texas Instruments Incorporated - http://www.ti.com/
 *	Andrew F. Davis <afd@ti.com>
 */

#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>


struct uncached_heap {
	struct dma_heap *heap;
};

struct uncached_heap_buffer {
	struct dma_heap *heap;
	struct list_head attachments;
	struct mutex lock;
	unsigned long len;
	struct sg_table sg_table;
	int vmap_cnt;
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
	struct uncached_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;
	struct sg_table *table;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	table = dup_sg_table(&buffer->sg_table);
	if (IS_ERR(table)) {
		kfree(a);
		return -ENOMEM;
	}

	a->table = table;
	a->dev = attachment->dev;
	INIT_LIST_HEAD(&a->list);

	attachment->priv = a;

	mutex_lock(&buffer->lock);
	list_add(&a->list, &buffer->attachments);
	mutex_unlock(&buffer->lock);

	return 0;
}

static void dma_heap_detatch(struct dma_buf *dmabuf,
			     struct dma_buf_attachment *attachment)
{
	struct uncached_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a = attachment->priv;

	mutex_lock(&buffer->lock);
	list_del(&a->list);
	mutex_unlock(&buffer->lock);

	sg_free_table(a->table);
	kfree(a->table);
	kfree(a);
}

static struct sg_table *dma_heap_map_dma_buf(struct dma_buf_attachment *attachment,
					     enum dma_data_direction direction)
{
	struct dma_heap_attachment *a = attachment->priv;
	struct sg_table *table = a->table;

	if (!dma_map_sg_attrs(attachment->dev, table->sgl, table->nents,
			      direction, DMA_ATTR_SKIP_CPU_SYNC|DMA_ATTR_WRITE_COMBINE))
		return ERR_PTR(-ENOMEM);

	return table;
}

static void dma_heap_unmap_dma_buf(struct dma_buf_attachment *attachment,
				   struct sg_table *table,
				   enum dma_data_direction direction)
{
	dma_unmap_sg_attrs(attachment->dev, table->sgl, table->nents,
			   direction, DMA_ATTR_SKIP_CPU_SYNC|DMA_ATTR_WRITE_COMBINE);
}

static int dma_heap_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct uncached_heap_buffer *buffer = dmabuf->priv;
	struct sg_table *table = &buffer->sg_table;
	unsigned long addr = vma->vm_start;
	unsigned long offset = vma->vm_pgoff * PAGE_SIZE;
	struct scatterlist *sg;
	int i;
	int ret;


	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	for_each_sg(table->sgl, sg, table->nents, i) {
		struct page *page = sg_page(sg);
		unsigned long remainder = vma->vm_end - addr;
		unsigned long len = sg->length;

		if (offset >= sg->length) {
			offset -= sg->length;
			continue;
		} else if (offset) {
			page += offset / PAGE_SIZE;
			len = sg->length - offset;
			offset = 0;
		}
		len = min(len, remainder);
		ret = remap_pfn_range(vma, addr, page_to_pfn(page), len,
				      vma->vm_page_prot);
		if (ret)
			return ret;
		addr += len;
		if (addr >= vma->vm_end)
			return 0;
	}
	return 0;
}



static void *dma_heap_do_vmap(struct uncached_heap_buffer *buffer)
{
	struct sg_table *table = &buffer->sg_table;
	int npages = PAGE_ALIGN(buffer->len) / PAGE_SIZE;
	struct page **pages = vmalloc(sizeof(struct page *) * npages);
	struct page **tmp = pages;
	struct scatterlist *sg;
	pgprot_t pgprot;
	void *vaddr;
	int i, j;

	if (!pages)
		return ERR_PTR(-ENOMEM);

	pgprot = pgprot_writecombine(PAGE_KERNEL);

	for_each_sg(table->sgl, sg, table->nents, i) {
		int npages_this_entry = PAGE_ALIGN(sg->length) / PAGE_SIZE;
		struct page *page = sg_page(sg);

		BUG_ON(i >= npages);
		for (j = 0; j < npages_this_entry; j++)
			*(tmp++) = page++;
	}
	vaddr = vmap(pages, npages, VM_MAP, pgprot);
	vfree(pages);

	if (!vaddr)
		return ERR_PTR(-ENOMEM);

	return vaddr;
}

static void *dma_heap_buffer_vmap_get(struct uncached_heap_buffer *buffer)
{
        void *vaddr;

        if (buffer->vmap_cnt) {
                buffer->vmap_cnt++;
                return buffer->vaddr;
        }
        vaddr = dma_heap_do_vmap(buffer);
        if (IS_ERR(vaddr))
                return vaddr;
        buffer->vaddr = vaddr;
        buffer->vmap_cnt++;
        return vaddr;
}

static void dma_heap_buffer_vmap_put(struct uncached_heap_buffer *buffer)
{
        if (!--buffer->vmap_cnt) {
                vunmap(buffer->vaddr);
                buffer->vaddr = NULL;
        }
}

static void *dma_heap_vmap(struct dma_buf *dmabuf)
{
        struct uncached_heap_buffer *buffer = dmabuf->priv;
        void *vaddr;

        mutex_lock(&buffer->lock);
        vaddr = dma_heap_buffer_vmap_get(buffer);
        mutex_unlock(&buffer->lock);

        return vaddr;
}

static void dma_heap_vunmap(struct dma_buf *dmabuf, void *vaddr)
{
	struct uncached_heap_buffer *buffer = dmabuf->priv;

        mutex_lock(&buffer->lock);
        dma_heap_buffer_vmap_put(buffer);
        mutex_unlock(&buffer->lock);
}

static void dma_heap_dma_buf_release(struct dma_buf *dmabuf)
{
	struct uncached_heap_buffer *buffer = dmabuf->priv;
	struct sg_table *table;
	struct scatterlist *sg;
	int i;

	table = &buffer->sg_table;
	for_each_sg(table->sgl, sg, table->nents, i)
                __free_page(sg_page(sg));
	sg_free_table(table);
	kfree(buffer);
}

const struct dma_buf_ops uncached_heap_buf_ops = {
	.attach = dma_heap_attach,
	.detach = dma_heap_detatch,
	.map_dma_buf = dma_heap_map_dma_buf,
	.unmap_dma_buf = dma_heap_unmap_dma_buf,
	.mmap = dma_heap_mmap,
	.vmap = dma_heap_vmap,
	.vunmap = dma_heap_vunmap,
	.release = dma_heap_dma_buf_release,
};

static int uncached_heap_allocate(struct dma_heap *heap,
				  unsigned long len,
				  unsigned long fd_flags,
				  unsigned long heap_flags)
{
	struct uncached_heap_buffer *buffer;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct dma_buf *dmabuf;
	struct sg_table *table;
	struct scatterlist *sg;
	pgoff_t pagecount;
	pgoff_t pg;
	int i, ret = -ENOMEM;

	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	INIT_LIST_HEAD(&buffer->attachments);
	mutex_init(&buffer->lock);
	buffer->heap = heap;
	buffer->len = len;

	table = &buffer->sg_table;
	pagecount = len/PAGE_SIZE;
	if (sg_alloc_table(table, pagecount, GFP_KERNEL))
		goto free_buffer;

	sg = table->sgl;
	for (pg = 0; pg < pagecount; pg++) {
		struct page *page;
		/*
		 * Avoid trying to allocate memory if the process
		 * has been killed by by SIGKILL
		 */
		if (fatal_signal_pending(current))
			goto free_pages;
		page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!page)
			goto free_pages;
		sg_set_page(sg, page, page_size(page), 0);

		/* XXX Super hack. Set the dma_address so the initial sync flushes the cpu cache */
		sg_dma_address(sg) = sg_phys(sg);

		sg = sg_next(sg);
	}


	/* create the dmabuf */
	exp_info.ops = &uncached_heap_buf_ops;
	exp_info.size = buffer->len;
	exp_info.flags = fd_flags;
	exp_info.priv = buffer;
	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto free_pages;
	}

	ret = dma_buf_fd(dmabuf, fd_flags);
	if (ret < 0) {
		dma_buf_put(dmabuf);
		/* just return, as put will call release and that will free */
		return ret;
	}

	/*
	 * XXX This is hackish. While the buffer will be uncached, we need
	 * to initially flush cpu cache, since the the __GFP_ZERO on the
	 * allocation means the zeroing was done by the cpu and thus it is likely
	 * cached. Flush it out now so we don't get corruption later on.
	 *
	 * Ideally we could do this without setting the sg_dma_address() above
	 * nor using the heap device as a dummy dev.
	 */
	dma_sync_sg_for_device(dma_heap_get_dev(heap), table->sgl, table->nents,
				DMA_BIDIRECTIONAL);

	return ret;

free_pages:
	for_each_sg(table->sgl, sg, table->nents, i)
                __free_page(sg_page(sg));
	sg_free_table(table);
free_buffer:
	kfree(buffer);

	return ret;
}

static struct dma_heap_ops uncached_heap_ops = {
	.allocate = uncached_heap_allocate,
};

static int uncached_heap_create(void)
{
	struct uncached_heap *heap;
	struct dma_heap_export_info exp_info;


	heap = kzalloc(sizeof(*heap), GFP_KERNEL);
	if (!heap)
		return -ENOMEM;

	/* Initialize any custom my_dma_heap structure values here */

	exp_info.name = "uncached";
	exp_info.ops = &uncached_heap_ops;
	exp_info.priv = heap;
	heap->heap = dma_heap_add(&exp_info);
	if (IS_ERR(heap->heap)) {
		int ret = PTR_ERR(heap->heap);
		kfree(heap);
		return ret;
	}

	return 0;
}
device_initcall(uncached_heap_create);

