// SPDX-License-Identifier: GPL-2.0
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <uapi/linux/dma-heap.h>

#include "heap-helpers.h"

void init_heap_helper_buffer(struct heap_helper_buffer *buffer,
			     void (*free)(struct heap_helper_buffer *))
{
	buffer->priv_virt = NULL;
	mutex_init(&buffer->lock);
	buffer->vmap_cnt = 0;
	buffer->vaddr = NULL;
	buffer->sg_table = NULL;
	INIT_LIST_HEAD(&buffer->attachments);
	buffer->free = free;
}
EXPORT_SYMBOL_GPL(init_heap_helper_buffer);

struct dma_buf *heap_helper_export_dmabuf(struct heap_helper_buffer *buffer,
					  int fd_flags)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	exp_info.ops = &heap_helper_ops;
	exp_info.size = buffer->size;
	exp_info.flags = fd_flags;
	exp_info.priv = buffer;

	return dma_buf_export(&exp_info);
}
EXPORT_SYMBOL_GPL(heap_helper_export_dmabuf);

static void *dma_heap_map_kernel(struct heap_helper_buffer *buffer)
{
	struct scatterlist *sg;
	int i, j;
	void *vaddr;
	pgprot_t pgprot;
	struct sg_table *table = buffer->sg_table;
	int npages = PAGE_ALIGN(buffer->size) / PAGE_SIZE;
	struct page **pages = vmalloc(array_size(npages,
						 sizeof(struct page *)));
	struct page **tmp = pages;

	if (!pages)
		return ERR_PTR(-ENOMEM);

	pgprot = PAGE_KERNEL;

	for_each_sg(table->sgl, sg, table->nents, i) {
		int npages_this_entry = PAGE_ALIGN(sg->length) / PAGE_SIZE;
		struct page *page = sg_page(sg);

		WARN_ON(i >= npages);
		for (j = 0; j < npages_this_entry; j++)
			*(tmp++) = nth_page(page, j);
	}
/* TODO: Comment from Christoph:
	That being said I really wish we could have a more iterative version
	of vmap, where the caller does a get_vm_area_caller and then adds
	each chunk using another call, including the possibility of mapping
	larger than PAGE_SIZE contigous ones.  Any chance you could look into
	that?
*/

	vaddr = vmap(pages, npages, VM_MAP, pgprot);
	vfree(pages);

	if (!vaddr)
		return ERR_PTR(-ENOMEM);

	return vaddr;
}

static void dma_heap_buffer_destroy(struct heap_helper_buffer *buffer)
{
	if (buffer->vmap_cnt > 0) {
		WARN(1, "%s: buffer still mapped in the kernel\n", __func__);
		vunmap(buffer->vaddr);
	}

	buffer->free(buffer);
}

static void *dma_heap_buffer_vmap_get(struct heap_helper_buffer *buffer)
{
	void *vaddr;

	if (buffer->vmap_cnt) {
		buffer->vmap_cnt++;
		return buffer->vaddr;
	}
	vaddr = dma_heap_map_kernel(buffer);
	if (IS_ERR(vaddr))
		return vaddr;
	buffer->vaddr = vaddr;
	buffer->vmap_cnt++;
	return vaddr;
}

static void dma_heap_buffer_vmap_put(struct heap_helper_buffer *buffer)
{
	if (!--buffer->vmap_cnt) {
		vunmap(buffer->vaddr);
		buffer->vaddr = NULL;
	}
}

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

static void free_duped_table(struct sg_table *table)
{
	sg_free_table(table);
	kfree(table);
}

struct dma_heaps_attachment {
	struct device *dev;
	struct sg_table *table;
	struct list_head list;
};

static int dma_heap_attach(struct dma_buf *dmabuf,
			   struct dma_buf_attachment *attachment)
{
	struct dma_heaps_attachment *a;
	struct sg_table *table;
	struct heap_helper_buffer *buffer = dmabuf->priv;

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

	mutex_lock(&buffer->lock);
	list_add(&a->list, &buffer->attachments);
	mutex_unlock(&buffer->lock);

	return 0;
}

static void dma_heap_detach(struct dma_buf *dmabuf,
			    struct dma_buf_attachment *attachment)
{
	struct dma_heaps_attachment *a = attachment->priv;
	struct heap_helper_buffer *buffer = dmabuf->priv;

	mutex_lock(&buffer->lock);
	list_del(&a->list);
	mutex_unlock(&buffer->lock);
	free_duped_table(a->table);

	kfree(a);
}

static
struct sg_table *dma_heap_map_dma_buf(struct dma_buf_attachment *attachment,
				      enum dma_data_direction direction)
{
	struct dma_heaps_attachment *a = attachment->priv;
	struct sg_table *table;

	table = a->table;

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

static int dma_heap_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct heap_helper_buffer *buffer = dmabuf->priv;
	struct sg_table *table = buffer->sg_table;
	unsigned long addr = vma->vm_start;
	unsigned long offset = vma->vm_pgoff * PAGE_SIZE;
	struct scatterlist *sg;
	int i;
	int ret = 0;

	if ((vma->vm_flags & (VM_SHARED | VM_MAYSHARE)) == 0)
		return -EINVAL;

	mutex_lock(&buffer->lock);
	/* now map it to userspace */
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
			goto unlock;
		addr += len;
		if (addr >= vma->vm_end) {
			ret = 0;
			goto unlock;
		}
	}
unlock:
	mutex_unlock(&buffer->lock);

	if (ret)
		pr_err("%s: failure mapping buffer to userspace\n",
		       __func__);

	return ret;
}

static void dma_heap_dma_buf_release(struct dma_buf *dmabuf)
{
	struct heap_helper_buffer *buffer = dmabuf->priv;

	dma_heap_buffer_destroy(buffer);
}

static int dma_heap_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
					     enum dma_data_direction direction)
{
	struct heap_helper_buffer *buffer = dmabuf->priv;
	struct dma_heaps_attachment *a;
	int ret = 0;

	mutex_lock(&buffer->lock);

	if (buffer->vmap_cnt)
		invalidate_kernel_vmap_range(buffer->vaddr, buffer->size);

	list_for_each_entry(a, &buffer->attachments, list) {
		dma_sync_sg_for_cpu(a->dev, a->table->sgl, a->table->nents,
				    direction);
	}
	mutex_unlock(&buffer->lock);

	return ret;
}

static int dma_heap_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
					   enum dma_data_direction direction)
{
	struct heap_helper_buffer *buffer = dmabuf->priv;
	struct dma_heaps_attachment *a;

	mutex_lock(&buffer->lock);

	if (buffer->vmap_cnt)
		flush_kernel_vmap_range(buffer->vaddr, buffer->size);

	list_for_each_entry(a, &buffer->attachments, list) {
		dma_sync_sg_for_device(a->dev, a->table->sgl, a->table->nents,
				       direction);
	}
	mutex_unlock(&buffer->lock);

	return 0;
}

static void *dma_heap_dma_buf_vmap(struct dma_buf *dmabuf)
{
	struct heap_helper_buffer *buffer = dmabuf->priv;
	void *vaddr;

	mutex_lock(&buffer->lock);
	vaddr = dma_heap_buffer_vmap_get(buffer);
	mutex_unlock(&buffer->lock);

	return vaddr;
}

static void dma_heap_dma_buf_vunmap(struct dma_buf *dmabuf, void *vaddr)
{
	struct heap_helper_buffer *buffer = dmabuf->priv;

	mutex_lock(&buffer->lock);
	dma_heap_buffer_vmap_put(buffer);
	mutex_unlock(&buffer->lock);
}

const struct dma_buf_ops heap_helper_ops = {
	.cache_sgt_mapping = true,
	.map_dma_buf = dma_heap_map_dma_buf,
	.unmap_dma_buf = dma_heap_unmap_dma_buf,
	.mmap = dma_heap_mmap,
	.release = dma_heap_dma_buf_release,
	.attach = dma_heap_attach,
	.detach = dma_heap_detach,
	.begin_cpu_access = dma_heap_dma_buf_begin_cpu_access,
	.end_cpu_access = dma_heap_dma_buf_end_cpu_access,
	.vmap = dma_heap_dma_buf_vmap,
	.vunmap = dma_heap_dma_buf_vunmap,
};
