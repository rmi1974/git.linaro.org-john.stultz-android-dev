#ifndef _LINUX_VRANGE_H
#define _LINUX_VRANGE_H

#include <linux/swap.h>
#include <linux/swapops.h>

#define VRANGE_NONVOLATILE 0
#define VRANGE_VOLATILE 1
#define VRANGE_VALID_FLAGS (0) /* Don't yet support any flags */

static inline swp_entry_t swp_entry_mk_vrange_purged(void)
{
	return swp_entry(SWP_VRANGE_PURGED, 0);
}

static inline int entry_is_vrange_purged(swp_entry_t entry)
{
	return swp_type(entry) == SWP_VRANGE_PURGED;
}

#endif /* _LINUX_VRANGE_H */
