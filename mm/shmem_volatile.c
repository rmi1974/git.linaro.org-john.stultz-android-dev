/*
 * memfd_create system call and file sealing support
 *
 * Code was originally included in shmem.c, and broken out to facilitate
 * use by hugetlbfs as well as tmpfs.
 *
 * This file is released under the GPL.
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/file.h>
#include <linux/falloc.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/khugepaged.h>
#include <linux/syscalls.h>
#include <linux/hugetlb.h>
#include <linux/shmem_fs.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/security.h>
#include <linux/mman.h>
#include <linux/uaccess.h>
#include <linux/personality.h>
#include <linux/bitops.h>
#include <linux/mutex.h>



/* Return values from ASHMEM_PIN: Was the mapping purged while unpinned? */
#define VRANGE_NOT_PURGED	0
#define VRANGE_WAS_PURGED	1

/* Return values from ASHMEM_GET_PIN_STATUS: Is the mapping pinned? */
#define VRANGE_IS_UNPINNED	0
#define VRANGE_IS_PINNED	1

static struct volatile_range {
	struct list_head lru;
	struct list_head unpinned;
	struct file *file;
	size_t pgstart;
	size_t pgend;
	unsigned int purged;
};

/*
 * vrange_mutex - protects the list of and each individual volatile_range
 *
 * Lock Ordering: ashmex_mutex -> i_mutex -> i_alloc_sem
 */
static DEFINE_MUTEX(vrange_mutex);

/* LRU list of unpinned pages, protected by vrange_mutex */
static LIST_HEAD(vrange_lru_list);

/*
 * long lru_count - The count of pages on our LRU list.
 *
 * This is protected by vrange_mutex.
 */
static unsigned long lru_count;

static struct kmem_cache *vrange_cachep __read_mostly;

static inline unsigned long range_size(struct volatile_range *range)
{
	return range->pgend - range->pgstart + 1;
}

static inline bool range_on_lru(struct volatile_range *range)
{
	return range->purged == VRANGE_NOT_PURGED;
}

static inline bool page_range_subsumes_range(struct volatile_range *range,
					     size_t start, size_t end)
{
	return (range->pgstart >= start) && (range->pgend <= end);
}

static inline bool page_range_subsumed_by_range(struct volatile_range *range,
						size_t start, size_t end)
{
	return (range->pgstart <= start) && (range->pgend >= end);
}

static inline bool page_in_range(struct volatile_range *range, size_t page)
{
	return (range->pgstart <= page) && (range->pgend >= page);
}

static inline bool page_range_in_range(struct volatile_range *range,
				       size_t start, size_t end)
{
	return page_in_range(range, start) || page_in_range(range, end) ||
		page_range_subsumes_range(range, start, end);
}

static inline bool range_before_page(struct volatile_range *range, size_t page)
{
	return range->pgend < page;
}


/**
 * lru_add() - Adds a range of memory to the LRU list
 * @range:     The memory range being added.
 *
 * The range is first added to the end (tail) of the LRU list.
 * After this, the size of the range is added to @lru_count
 */
static inline void lru_add(struct volatile_range *range)
{
	list_add_tail(&range->lru, &vrange_lru_list);
	lru_count += range_size(range);
}

/**
 * lru_del() - Removes a range of memory from the LRU list
 * @range:     The memory range being removed
 *
 * The range is first deleted from the LRU list.
 * After this, the size of the range is removed from @lru_count
 */
static inline void lru_del(struct volatile_range *range)
{
	list_del(&range->lru);
	lru_count -= range_size(range);
}

/**
 * range_alloc() - Allocates and initializes a new volatile_range structure
 * @file:	   The associated file
 * @prev_range:	   The previous volatile_range in the sorted asma->unpinned list
 * @purged:	   Initial purge status (ASMEM_NOT_PURGED or ASHMEM_WAS_PURGED)
 * @start:	   The starting page (inclusive)
 * @end:	   The ending page (inclusive)
 *
 * This function is protected by vrange_mutex.
 *
 * Return: 0 if successful, or -ENOMEM if there is an error
 */
static int range_alloc(struct file *file,
		       struct volatile_range *prev_range, unsigned int purged,
		       size_t start, size_t end)
{
	struct volatile_range *range;

	range = kmem_cache_zalloc(vrange_cachep, GFP_KERNEL);
	if (unlikely(!range))
		return -ENOMEM;

	range->file = file;
	range->pgstart = start;
	range->pgend = end;
	range->purged = purged;

	list_add_tail(&range->unpinned, &prev_range->unpinned);

	if (range_on_lru(range))
		lru_add(range);

	return 0;
}

/**
 * range_del() - Deletes and dealloctes an volatile_range structure
 * @range:	 The associated volatile_range that has previously been allocated
 */
static void range_del(struct volatile_range *range)
{
	list_del(&range->unpinned);
	if (range_on_lru(range))
		lru_del(range);
	kmem_cache_free(vrange_cachep, range);
}

/**
 * range_shrink() - Shrinks a volatile_range
 * @range:	    The associated volatile_range being shrunk
 * @start:	    The starting byte of the new range
 * @end:	    The ending byte of the new range
 *
 * This does not modify the data inside the existing range in any way - It
 * simply shrinks the boundaries of the range.
 *
 * Theoretically, with a little tweaking, this could eventually be changed
 * to range_resize, and expand the lru_count if the new range is larger.
 */
static inline void range_shrink(struct volatile_range *range,
				size_t start, size_t end)
{
	size_t pre = range_size(range);

	range->pgstart = start;
	range->pgend = end;

	if (range_on_lru(range))
		lru_count -= pre - range_size(range);
}



/*
 * vrange_pin - pin the given region, returning whether it was
 * previously purged (VRANGE_WAS_PURGED) or not (VRANGE_NOT_PURGED).
 *
 * Caller must hold vrange_mutex.
 */
static int vrange_pin(struct file *file, size_t pgstart, size_t pgend)
{
	struct list_head *unpinned_list = &SHMEM_I(file_inode(file))->volatile_list;
	struct volatile_range *range, *next;
	int ret = VRANGE_NOT_PURGED;

	list_for_each_entry_safe(range, next, unpinned_list, unpinned) {
		/* moved past last applicable page; we can short circuit */
		if (range_before_page(range, pgstart))
			break;

		/*
		 * The user can ask us to pin pages that span multiple ranges,
		 * or to pin pages that aren't even unpinned, so this is messy.
		 *
		 * Four cases:
		 * 1. The requested range subsumes an existing range, so we
		 *    just remove the entire matching range.
		 * 2. The requested range overlaps the start of an existing
		 *    range, so we just update that range.
		 * 3. The requested range overlaps the end of an existing
		 *    range, so we just update that range.
		 * 4. The requested range punches a hole in an existing range,
		 *    so we have to update one side of the range and then
		 *    create a new range for the other side.
		 */
		if (page_range_in_range(range, pgstart, pgend)) {
			ret |= range->purged;

			/* Case #1: Easy. Just nuke the whole thing. */
			if (page_range_subsumes_range(range, pgstart, pgend)) {
				range_del(range);
				continue;
			}

			/* Case #2: We overlap from the start, so adjust it */
			if (range->pgstart >= pgstart) {
				range_shrink(range, pgend + 1, range->pgend);
				continue;
			}

			/* Case #3: We overlap from the rear, so adjust it */
			if (range->pgend <= pgend) {
				range_shrink(range, range->pgstart,
					     pgstart - 1);
				continue;
			}

			/*
			 * Case #4: We eat a chunk out of the middle. A bit
			 * more complicated, we allocate a new range for the
			 * second half and adjust the first chunk's endpoint.
			 */
			range_alloc(file, range, range->purged,
				    pgend + 1, range->pgend);
			range_shrink(range, range->pgstart, pgstart - 1);
			break;
		}
	}

	return ret;
}

/*
 * vrange_unpin - unpin the given range of pages. Returns zero on success.
 *
 * Caller must hold vrange_mutex.
 */
static int vrange_unpin(struct file *file, size_t pgstart, size_t pgend)
{
	struct volatile_range *range, *next;
	unsigned int purged = VRANGE_NOT_PURGED;
	struct list_head *unpinned_list = &SHMEM_I(file_inode(file))->volatile_list;

restart:
	list_for_each_entry_safe(range, next, unpinned_list, unpinned) {
		/* short circuit: this is our insertion point */
		if (range_before_page(range, pgstart))
			break;

		/*
		 * The user can ask us to unpin pages that are already entirely
		 * or partially pinned. We handle those two cases here.
		 */
		if (page_range_subsumed_by_range(range, pgstart, pgend))
			return 0;
		if (page_range_in_range(range, pgstart, pgend)) {
			pgstart = min(range->pgstart, pgstart);
			pgend = max(range->pgend, pgend);
			purged |= range->purged;
			range_del(range);
			goto restart;
		}
	}

	return range_alloc(file, range, purged, pgstart, pgend);
}

long volatile_range_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct f_vrange_pin pin;
	size_t pgstart, pgend;
	long error = -EINVAL;

	if (copy_from_user(&pin, argp, sizeof(pin)))
		return -EFAULT;

	mutex_lock(&vrange_mutex);

	if (unlikely(!file))
		goto out_unlock;

	/* per custom, you can pass zero for len to mean "everything onward" */
//	if (!pin.l_len)
//		pin.len = PAGE_ALIGN(asma->size) - pin.l_offset;

	if (unlikely((pin.l_offset | pin.l_len) & ~PAGE_MASK))
		goto out_unlock;

	if (unlikely(((u64)-1) - pin.l_offset < pin.l_len))
		goto out_unlock;

//	if (unlikely(PAGE_ALIGN(asma->size) < pin.l_offset + pin.l_len))
//		goto out_unlock;

	pgstart = pin.l_offset / PAGE_SIZE;
	pgend = pgstart + (pin.l_len / PAGE_SIZE) - 1;

	switch (cmd) {
	case F_VRANGE_UNPIN:
		error = vrange_pin(file, pgstart, pgend);
		break;
	case F_VRANGE_PIN:
		error = vrange_unpin(file, pgstart, pgend);
		break;
	default:
		break;
	}


out_unlock:
	mutex_unlock(&vrange_mutex);


	return error;
}

/**
 * volatile_range_release() - Releases an Anonymous Shared Memory structure
 * @ignored:	      The backing file's Index Node(?) - It is ignored here.
 * @file:	      The backing file
 *
 * Return: 0 if successful. If it is anything else, go have a coffee and
 * try again.
 */
int volatile_range_release(struct inode *ignored, struct file *file)
{
	struct volatile_range *range, *next;
	struct list_head *unpinned_list = &SHMEM_I(file_inode(file))->volatile_list;

	mutex_lock(&vrange_mutex);
	list_for_each_entry_safe(range, next, unpinned_list, unpinned)
		range_del(range);
	mutex_unlock(&vrange_mutex);
	return 0;
}




/*
 * vrange_shrink - our cache shrinker, called from mm/vmscan.c
 *
 * 'nr_to_scan' is the number of objects to scan for freeing.
 *
 * 'gfp_mask' is the mask of the allocation that got us into this mess.
 *
 * Return value is the number of objects freed or -1 if we cannot
 * proceed without risk of deadlock (due to gfp_mask).
 *
 * We approximate LRU via least-recently-unpinned, jettisoning unpinned partial
 * chunks of volatile regions LRU-wise one-at-a-time until we hit 'nr_to_scan'
 * pages freed.
 */
static unsigned long
vrange_shrink_scan(struct shrinker *shrink, struct shrink_control *sc)
{
	struct volatile_range *range, *next;
	unsigned long freed = 0;

	/* We might recurse into filesystem code, so bail out if necessary */
	if (!(sc->gfp_mask & __GFP_FS))
		return SHRINK_STOP;

	if (!mutex_trylock(&vrange_mutex))
		return -1;

	list_for_each_entry_safe(range, next, &vrange_lru_list, lru) {
		loff_t start = range->pgstart * PAGE_SIZE;
		loff_t end = (range->pgend + 1) * PAGE_SIZE;

		vfs_fallocate(range->file,
			      FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
			      start, end - start);
		range->purged = VRANGE_WAS_PURGED;
		lru_del(range);

		freed += range_size(range);
		if (--sc->nr_to_scan <= 0)
			break;
	}
	mutex_unlock(&vrange_mutex);
	return freed;
}

static unsigned long
vrange_shrink_count(struct shrinker *shrink, struct shrink_control *sc)
{
	/*
	 * note that lru_count is count of pages on the lru, not a count of
	 * objects on the list. This means the scan function needs to return the
	 * number of pages freed, not the number of objects scanned.
	 */
	return lru_count;
}

static struct shrinker vrange_shrinker = {
	.count_objects = vrange_shrink_count,
	.scan_objects = vrange_shrink_scan,
	/*
	 * XXX (dchinner): I wish people would comment on why they need on
	 * significant changes to the default value here
	 */
	.seeks = DEFAULT_SEEKS * 4,
};


static int __init vrange_init(void)
{
	int ret = -ENOMEM;

	vrange_cachep = kmem_cache_create("volatile_range_cache",
						sizeof(struct volatile_range),
						0, 0, NULL);
	if (unlikely(!vrange_cachep)) {
		pr_err("failed to create slab cache\n");
		return ret;
	}

	ret = register_shrinker(&vrange_shrinker);
	if (ret) {
		pr_err("failed to register shrinker!\n");
		goto out;
	}

	pr_info("initialized\n");

	return 0;

out:
	kmem_cache_destroy(vrange_cachep);
	return ret;
}
device_initcall(vrange_init);

