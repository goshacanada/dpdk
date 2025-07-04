/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017-2018 Intel Corporation
 */

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_eal_paging.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_spinlock.h>

#include <eal_export.h>
#include "eal_filesystem.h"
#include "eal_private.h"

#include "rte_fbarray.h"

#define MASK_SHIFT 6ULL
#define MASK_ALIGN (1ULL << MASK_SHIFT)
#define MASK_LEN_TO_IDX(x) ((x) >> MASK_SHIFT)
#define MASK_LEN_TO_MOD(x) ((x) - RTE_ALIGN_FLOOR(x, MASK_ALIGN))
#define MASK_GET_IDX(idx, mod) ((idx << MASK_SHIFT) + mod)

/*
 * We use this to keep track of created/attached memory areas to prevent user
 * errors in API usage.
 */
struct mem_area {
	TAILQ_ENTRY(mem_area) next;
	void *addr;
	size_t len;
	int fd;
};
TAILQ_HEAD(mem_area_head, mem_area);
/* local per-process tailq */
static struct mem_area_head mem_area_tailq =
	TAILQ_HEAD_INITIALIZER(mem_area_tailq);
static rte_spinlock_t mem_area_lock = RTE_SPINLOCK_INITIALIZER;

/*
 * This is a mask that is always stored at the end of array, to provide fast
 * way of finding free/used spots without looping through each element.
 */

struct used_mask {
	unsigned int n_masks;
	uint64_t data[];
};

static size_t
calc_mask_size(unsigned int len)
{
	/* mask must be multiple of MASK_ALIGN, even though length of array
	 * itself may not be aligned on that boundary.
	 */
	len = RTE_ALIGN_CEIL(len, MASK_ALIGN);
	return sizeof(struct used_mask) +
			sizeof(uint64_t) * MASK_LEN_TO_IDX(len);
}

static size_t
calc_data_size(size_t page_sz, unsigned int elt_sz, unsigned int len)
{
	size_t data_sz = elt_sz * len;
	size_t msk_sz = calc_mask_size(len);
	return RTE_ALIGN_CEIL(data_sz + msk_sz, page_sz);
}

static struct used_mask *
get_used_mask(void *data, unsigned int elt_sz, unsigned int len)
{
	return (struct used_mask *) RTE_PTR_ADD(data, elt_sz * len);
}

static int
resize_and_map(int fd, const char *path, void *addr, size_t len)
{
	void *map_addr;

	if (eal_file_truncate(fd, len)) {
		EAL_LOG(ERR, "Cannot truncate %s", path);
		return -1;
	}

	map_addr = rte_mem_map(addr, len, RTE_PROT_READ | RTE_PROT_WRITE,
			RTE_MAP_SHARED | RTE_MAP_FORCE_ADDRESS, fd, 0);
	if (map_addr != addr) {
		return -1;
	}
	return 0;
}

static int
overlap(const struct mem_area *ma, const void *start, size_t len)
{
	const void *end = RTE_PTR_ADD(start, len);
	const void *ma_start = ma->addr;
	const void *ma_end = RTE_PTR_ADD(ma->addr, ma->len);

	/* start overlap? */
	if (start >= ma_start && start < ma_end)
		return 1;
	/* end overlap? */
	if (end > ma_start && end < ma_end)
		return 1;
	return 0;
}

static int
find_next_n(const struct rte_fbarray *arr, unsigned int start, unsigned int n,
	    bool used)
{
	const struct used_mask *msk = get_used_mask(arr->data, arr->elt_sz,
			arr->len);
	unsigned int msk_idx, first, first_mod;
	unsigned int last, last_mod;
	uint64_t last_msk, first_msk;
	unsigned int run_start, left = 0;
	bool run_started = false;

	/*
	 * mask only has granularity of MASK_ALIGN, but start may not be aligned
	 * on that boundary, so construct a special mask to exclude anything we
	 * don't want to see to avoid confusing ctz.
	 */
	first = MASK_LEN_TO_IDX(start);
	first_mod = MASK_LEN_TO_MOD(start);
	first_msk = ~((1ULL << first_mod) - 1);

	/* array length may not be aligned, so calculate ignore mask for last
	 * mask index.
	 */
	last = MASK_LEN_TO_IDX(arr->len);
	last_mod = MASK_LEN_TO_MOD(arr->len);
	last_msk = ~(UINT64_MAX << last_mod);

	left = n;

	for (msk_idx = first; msk_idx < msk->n_masks; msk_idx++) {
		unsigned int s_idx, clz, need;
		uint64_t cur_msk, tmp_msk;

		/*
		 * In order to find N consecutive bits for arbitrary N, we need
		 * to be aware of the following:
		 *
		 *  1. To find N number of consecutive bits within a mask, we
		 *     need to do N-1 rshift-ands and see if we still have set
		 *     bits anywhere in the mask
		 *  2. N may be larger than mask size, in which case we need to
		 *     do a search in multiple consecutive masks
		 *  3. For multi-mask search to be meaningful, we need to anchor
		 *     our searches, i.e. first we find a run of M bits at the
		 *     end of current mask, then we look for N-M bits at the
		 *     beginning of next mask (or multiple masks)
		 *
		 * With all of the above, the algorithm looks as follows:
		 *
		 *  1. let N be the number of consecutive bits we're looking for
		 *  2. if we already started a run, check if we can continue it
		 *     by looking for remainder of N at the beginning of current
		 *     mask
		 *  3. if we lost a run or if we never had a run, we look for N
		 *     bits anywhere within the current mask (up to mask size,
		 *     we can finish this run in the next mask if N > mask size)
		 *  4. if we didn't find anything up to this point, check if any
		 *     topmost bits of the mask are set (meaning we can start a
		 *     run and finish it in the next mask)
		 *  5. at any point in steps 2-4, we may do an early exit due to
		 *     finding what we were looking for, or continue searching
		 *     further
		 */
		cur_msk = msk->data[msk_idx];

		/* if we're looking for free spaces, invert the mask */
		if (!used)
			cur_msk = ~cur_msk;

		/* first and last mask may not be aligned */
		if (msk_idx == first)
			cur_msk &= first_msk;
		if (msk_idx == last)
			cur_msk &= last_msk;

		/* do we have an active previous run? */
		if (run_started) {
			/* figure out how many consecutive bits we need here */
			need = RTE_MIN(left, MASK_ALIGN);

			/* see if we get a run of needed length */
			tmp_msk = cur_msk;
			for (s_idx = 0; s_idx < need - 1; s_idx++)
				tmp_msk &= tmp_msk >> 1ULL;

			/* if first bit is set, we keep the run */
			if (tmp_msk & 1) {
				left -= need;

				/* did we find what we were looking for? */
				if (left == 0)
					return run_start;

				/* keep looking */
				continue;
			}
			/* we lost the run, reset */
			run_started = false;
			left = n;
		}

		/* if we're here, we either lost the run or never had it */

		/* figure out how many consecutive bits we need here */
		need = RTE_MIN(left, MASK_ALIGN);

		/* do a search */
		tmp_msk = cur_msk;
		for (s_idx = 0; s_idx < need - 1; s_idx++)
			tmp_msk &= tmp_msk >> 1ULL;

		/* have we found something? */
		if (tmp_msk != 0) {
			/* figure out where the run started */
			run_start = MASK_GET_IDX(msk_idx, rte_ctz64(tmp_msk));
			run_started = true;
			left -= need;

			/* do we need to look further? */
			if (left == 0)
				return run_start;

			/* we need to keep looking */
			continue;
		}

		/* we didn't find our run within current mask, go for plan B. */

		/* count leading zeroes on inverted mask */
		clz = rte_clz64(~cur_msk);

		/* if there aren't any set bits at the end, just continue */
		if (clz == 0)
			continue;

		/* we have a partial run at the end */
		run_start = MASK_GET_IDX(msk_idx, MASK_ALIGN - clz);
		run_started = true;
		left -= clz;

		/* we'll figure this out in the next iteration */
	}
	/* we didn't find anything */
	rte_errno = used ? ENOENT : ENOSPC;
	return -1;
}

static int
find_next(const struct rte_fbarray *arr, unsigned int start, bool used)
{
	const struct used_mask *msk = get_used_mask(arr->data, arr->elt_sz,
			arr->len);
	unsigned int idx, first, first_mod;
	unsigned int last, last_mod;
	uint64_t last_msk, ignore_msk;

	/*
	 * mask only has granularity of MASK_ALIGN, but start may not be aligned
	 * on that boundary, so construct a special mask to exclude anything we
	 * don't want to see to avoid confusing ctz.
	 */
	first = MASK_LEN_TO_IDX(start);
	first_mod = MASK_LEN_TO_MOD(start);
	ignore_msk = ~((1ULL << first_mod) - 1ULL);

	/* array length may not be aligned, so calculate ignore mask for last
	 * mask index.
	 */
	last = MASK_LEN_TO_IDX(arr->len);
	last_mod = MASK_LEN_TO_MOD(arr->len);
	last_msk = ~(-(1ULL) << last_mod);

	for (idx = first; idx < msk->n_masks; idx++) {
		uint64_t cur = msk->data[idx];
		int found;

		/* if we're looking for free entries, invert mask */
		if (!used)
			cur = ~cur;

		if (idx == last)
			cur &= last_msk;

		/* ignore everything before start on first iteration */
		if (idx == first)
			cur &= ignore_msk;

		/* check if we have any entries */
		if (cur == 0)
			continue;

		/*
		 * find first set bit - that will correspond to whatever it is
		 * that we're looking for.
		 */
		found = rte_ctz64(cur);
		return MASK_GET_IDX(idx, found);
	}
	/* we didn't find anything */
	rte_errno = used ? ENOENT : ENOSPC;
	return -1;
}

static int
find_contig(const struct rte_fbarray *arr, unsigned int start, bool used)
{
	const struct used_mask *msk = get_used_mask(arr->data, arr->elt_sz,
			arr->len);
	unsigned int idx, first, first_mod;
	unsigned int last, last_mod;
	uint64_t last_msk;
	unsigned int need_len, result = 0;

	/* array length may not be aligned, so calculate ignore mask for last
	 * mask index.
	 */
	last = MASK_LEN_TO_IDX(arr->len);
	last_mod = MASK_LEN_TO_MOD(arr->len);
	last_msk = ~(-(1ULL) << last_mod);

	first = MASK_LEN_TO_IDX(start);
	first_mod = MASK_LEN_TO_MOD(start);
	for (idx = first; idx < msk->n_masks; idx++, result += need_len) {
		uint64_t cur = msk->data[idx];
		unsigned int run_len;

		need_len = MASK_ALIGN;

		/* if we're looking for free entries, invert mask */
		if (!used)
			cur = ~cur;

		/* if this is last mask, ignore everything after last bit */
		if (idx == last)
			cur &= last_msk;

		/* ignore everything before start on first iteration */
		if (idx == first) {
			cur >>= first_mod;
			/* at the start, we don't need the full mask len */
			need_len -= first_mod;
		}

		/* we will be looking for zeroes, so invert the mask */
		cur = ~cur;

		/* if mask is zero, we have a complete run */
		if (cur == 0)
			continue;

		/*
		 * see if current run ends before mask end.
		 */
		run_len = rte_ctz64(cur);

		/* add however many zeroes we've had in the last run and quit */
		if (run_len < need_len) {
			result += run_len;
			break;
		}
	}
	return result;
}

static int
find_prev_n(const struct rte_fbarray *arr, unsigned int start, unsigned int n,
		bool used)
{
	const struct used_mask *msk = get_used_mask(arr->data, arr->elt_sz,
			arr->len);
	/* we're going backwards so we need negative space */
	int64_t msk_idx;
	unsigned int first, first_mod;
	uint64_t first_msk;
	unsigned int run_end, left;
	bool run_started = false;

	/*
	 * mask only has granularity of MASK_ALIGN, but start may not be aligned
	 * on that boundary, so construct a special mask to exclude anything we
	 * don't want to see to avoid confusing clz. this "first" mask is
	 * actually our last because we're going backwards, so no second mask
	 * is required like in find_next_n case.
	 */
	first = MASK_LEN_TO_IDX(start);
	first_mod = MASK_LEN_TO_MOD(start);
	/* we're going backwards, so mask must start from the top */
	first_msk = first_mod == MASK_ALIGN - 1 ?
				UINT64_MAX : /* prevent overflow */
				~(UINT64_MAX << (first_mod + 1));

	left = n;

	/* go backwards, include zero */
	for (msk_idx = first; msk_idx >= 0; msk_idx--) {
		unsigned int s_idx, ctz, need;
		uint64_t cur_msk, tmp_msk;

		/*
		 * In order to find N consecutive bits for arbitrary N, we need
		 * to be aware of the following:
		 *
		 *  1. To find N number of consecutive bits within a mask, we
		 *     need to do N-1 lshift-ands and see if we still have set
		 *     bits anywhere in the mask
		 *  2. N may be larger than mask size, in which case we need to
		 *     do a search in multiple consecutive masks
		 *  3. For multi-mask search to be meaningful, we need to anchor
		 *     our searches, i.e. first we find a run of M bits at the
		 *     beginning of current mask, then we look for N-M bits at
		 *     the end of previous mask (or multiple masks)
		 *
		 * With all of the above, the algorithm looks as follows:
		 *
		 *  1. let N be the number of consecutive bits we're looking for
		 *  2. if we already started a run, check if we can continue it
		 *     by looking for remainder of N at the end of current mask
		 *  3. if we lost a run or if we never had a run, we look for N
		 *     bits anywhere within the current mask (up to mask size,
		 *     we can finish this run in the previous mask if N > mask
		 *     size)
		 *  4. if we didn't find anything up to this point, check if any
		 *     first bits of the mask are set (meaning we can start a
		 *     run and finish it in the previous mask)
		 *  5. at any point in steps 2-4, we may do an early exit due to
		 *     finding what we were looking for, or continue searching
		 *     further
		 */
		cur_msk = msk->data[msk_idx];

		/* if we're looking for free spaces, invert the mask */
		if (!used)
			cur_msk = ~cur_msk;

		/* first mask may not be aligned */
		if (msk_idx == first)
			cur_msk &= first_msk;

		/* do we have an active previous run? */
		if (run_started) {
			uint64_t last_bit = 0x1ULL << (MASK_ALIGN - 1);

			/* figure out how many consecutive bits we need here */
			need = RTE_MIN(left, MASK_ALIGN);

			/* see if we get a run of needed length */
			tmp_msk = cur_msk;
			for (s_idx = 0; s_idx < need - 1; s_idx++)
				tmp_msk &= tmp_msk << 1ULL;

			/* if last bit is set, we keep the run */
			if (tmp_msk & last_bit) {
				left -= need;

				/* did we find what we were looking for? */
				if (left == 0)
					return run_end - n;

				/* keep looking */
				continue;
			}
			/* we lost the run, reset */
			run_started = false;
			left = n;
		}

		/* if we're here, we either lost the run or never had it */

		/* figure out how many consecutive bits we need here */
		need = RTE_MIN(left, MASK_ALIGN);

		/* do a search */
		tmp_msk = cur_msk;
		for (s_idx = 0; s_idx < need - 1; s_idx++)
			tmp_msk &= tmp_msk << 1ULL;

		/* have we found something? */
		if (tmp_msk != 0) {
			/* figure out where the run started */
			run_end = MASK_GET_IDX(msk_idx, MASK_ALIGN - rte_clz64(tmp_msk));
			run_started = true;
			left -= need;

			/* do we need to look further? */
			if (left == 0)
				return run_end - n;

			/* we need to keep looking */
			continue;
		}

		/* we didn't find our run within current mask, go for plan B. */

		/* count trailing zeroes on inverted mask */
		ctz = rte_ctz64(~cur_msk);

		/* if there aren't any set bits at the beginning, just continue */
		if (ctz == 0)
			continue;

		/* we have a partial run at the beginning */
		run_end = MASK_GET_IDX(msk_idx, ctz);
		run_started = true;
		left -= ctz;

		/* we'll figure this out in the next iteration */
	}
	/* we didn't find anything */
	rte_errno = used ? ENOENT : ENOSPC;
	return -1;
}

static int
find_prev(const struct rte_fbarray *arr, unsigned int start, bool used)
{
	const struct used_mask *msk = get_used_mask(arr->data, arr->elt_sz,
			arr->len);
	unsigned int idx, first, first_mod;
	uint64_t ignore_msk;

	/*
	 * mask only has granularity of MASK_ALIGN, but start may not be aligned
	 * on that boundary, so construct a special mask to exclude anything we
	 * don't want to see to avoid confusing clz.
	 */
	first = MASK_LEN_TO_IDX(start);
	first_mod = MASK_LEN_TO_MOD(start);
	/* we're going backwards, so mask must start from the top */
	ignore_msk = first_mod == MASK_ALIGN - 1 ?
				UINT64_MAX : /* prevent overflow */
				~(UINT64_MAX << (first_mod + 1));

	/* go backwards, include zero */
	idx = first;
	do {
		uint64_t cur = msk->data[idx];
		int found;

		/* if we're looking for free entries, invert mask */
		if (!used)
			cur = ~cur;

		/* ignore everything before start on first iteration */
		if (idx == first)
			cur &= ignore_msk;

		/* check if we have any entries */
		if (cur == 0)
			continue;

		/*
		 * find last set bit - that will correspond to whatever it is
		 * that we're looking for. we're counting trailing zeroes, thus
		 * the value we get is counted from end of mask, so calculate
		 * position from start of mask.
		 */
		found = MASK_ALIGN - rte_clz64(cur) - 1;

		return MASK_GET_IDX(idx, found);
	} while (idx-- != 0); /* decrement after check  to include zero*/

	/* we didn't find anything */
	rte_errno = used ? ENOENT : ENOSPC;
	return -1;
}

static int
find_rev_contig(const struct rte_fbarray *arr, unsigned int start, bool used)
{
	const struct used_mask *msk = get_used_mask(arr->data, arr->elt_sz,
			arr->len);
	unsigned int idx, first, first_mod;
	unsigned int need_len, result = 0;

	first = MASK_LEN_TO_IDX(start);
	first_mod = MASK_LEN_TO_MOD(start);

	/* go backwards, include zero */
	idx = first;
	do {
		uint64_t cur = msk->data[idx];
		unsigned int run_len;

		need_len = MASK_ALIGN;

		/* if we're looking for free entries, invert mask */
		if (!used)
			cur = ~cur;

		/* ignore everything after start on first iteration */
		if (idx == first) {
			unsigned int end_len = MASK_ALIGN - first_mod - 1;
			cur <<= end_len;
			/* at the start, we don't need the full mask len */
			need_len -= end_len;
		}

		/* we will be looking for zeroes, so invert the mask */
		cur = ~cur;

		/* if mask is zero, we have a complete run */
		if (cur == 0)
			goto endloop;

		/*
		 * see where run ends, starting from the end.
		 */
		run_len = rte_clz64(cur);

		/* add however many zeroes we've had in the last run and quit */
		if (run_len < need_len) {
			result += run_len;
			break;
		}
endloop:
		result += need_len;
	} while (idx-- != 0); /* decrement after check to include zero */
	return result;
}

static int
set_used(struct rte_fbarray *arr, unsigned int idx, bool used)
{
	struct used_mask *msk;
	uint64_t msk_bit = 1ULL << MASK_LEN_TO_MOD(idx);
	unsigned int msk_idx = MASK_LEN_TO_IDX(idx);
	bool already_used;
	int ret = -1;

	if (arr == NULL || idx >= arr->len) {
		rte_errno = EINVAL;
		return -1;
	}
	msk = get_used_mask(arr->data, arr->elt_sz, arr->len);
	ret = 0;

	/* prevent array from changing under us */
	rte_rwlock_write_lock(&arr->rwlock);

	already_used = (msk->data[msk_idx] & msk_bit) != 0;

	/* nothing to be done */
	if (used == already_used)
		goto out;

	if (used) {
		msk->data[msk_idx] |= msk_bit;
		arr->count++;
	} else {
		msk->data[msk_idx] &= ~msk_bit;
		arr->count--;
	}
out:
	rte_rwlock_write_unlock(&arr->rwlock);

	return ret;
}

static int
fully_validate(const char *name, unsigned int elt_sz, unsigned int len)
{
	if (name == NULL || elt_sz == 0 || len == 0 || len > INT_MAX) {
		rte_errno = EINVAL;
		return -1;
	}

	if (strnlen(name, RTE_FBARRAY_NAME_LEN) == RTE_FBARRAY_NAME_LEN) {
		rte_errno = ENAMETOOLONG;
		return -1;
	}
	return 0;
}

RTE_EXPORT_SYMBOL(rte_fbarray_init)
int
rte_fbarray_init(struct rte_fbarray *arr, const char *name, unsigned int len,
		unsigned int elt_sz)
{
	size_t page_sz, mmap_len;
	char path[PATH_MAX];
	struct used_mask *msk;
	struct mem_area *ma = NULL;
	void *data = NULL;
	int fd = -1;
	const struct internal_config *internal_conf =
		eal_get_internal_configuration();

	if (arr == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	if (fully_validate(name, elt_sz, len))
		return -1;

	/* allocate mem area before doing anything */
	ma = malloc(sizeof(*ma));
	if (ma == NULL) {
		rte_errno = ENOMEM;
		return -1;
	}

	page_sz = rte_mem_page_size();
	if (page_sz == (size_t)-1) {
		free(ma);
		return -1;
	}

	/* calculate our memory limits */
	mmap_len = calc_data_size(page_sz, elt_sz, len);

	data = eal_get_virtual_area(NULL, &mmap_len, page_sz, 0, 0);
	if (data == NULL) {
		free(ma);
		return -1;
	}

	rte_spinlock_lock(&mem_area_lock);

	fd = -1;

	if (internal_conf->no_shconf) {
		/* remap virtual area as writable */
		static const int flags = RTE_MAP_FORCE_ADDRESS |
			RTE_MAP_PRIVATE | RTE_MAP_ANONYMOUS;
		void *new_data = rte_mem_map(data, mmap_len,
			RTE_PROT_READ | RTE_PROT_WRITE, flags, fd, 0);
		if (new_data == NULL) {
			EAL_LOG(DEBUG, "%s(): couldn't remap anonymous memory: %s",
					__func__, rte_strerror(rte_errno));
			goto fail;
		}
	} else {
		eal_get_fbarray_path(path, sizeof(path), name);

		/*
		 * Each fbarray is unique to process namespace, i.e. the
		 * filename depends on process prefix. Try to take out a lock
		 * and see if we succeed. If we don't, someone else is using it
		 * already.
		 */
		fd = eal_file_open(path, EAL_OPEN_CREATE | EAL_OPEN_READWRITE);
		if (fd < 0) {
			EAL_LOG(DEBUG, "%s(): couldn't open %s: %s",
				__func__, path, rte_strerror(rte_errno));
			goto fail;
		} else if (eal_file_lock(
				fd, EAL_FLOCK_EXCLUSIVE, EAL_FLOCK_RETURN)) {
			EAL_LOG(DEBUG, "%s(): couldn't lock %s: %s",
				__func__, path, rte_strerror(rte_errno));
			rte_errno = EBUSY;
			goto fail;
		}

		/* take out a non-exclusive lock, so that other processes could
		 * still attach to it, but no other process could reinitialize
		 * it.
		 */
		if (eal_file_lock(fd, EAL_FLOCK_SHARED, EAL_FLOCK_RETURN))
			goto fail;

		if (resize_and_map(fd, path, data, mmap_len))
			goto fail;
	}
	ma->addr = data;
	ma->len = mmap_len;
	ma->fd = fd;

	/* do not close fd - keep it until detach/destroy */
	TAILQ_INSERT_TAIL(&mem_area_tailq, ma, next);

	/* initialize the data */
	memset(data, 0, mmap_len);

	/* populate data structure */
	strlcpy(arr->name, name, sizeof(arr->name));
	arr->data = data;
	arr->len = len;
	arr->elt_sz = elt_sz;
	arr->count = 0;

	msk = get_used_mask(data, elt_sz, len);
	msk->n_masks = MASK_LEN_TO_IDX(RTE_ALIGN_CEIL(len, MASK_ALIGN));

	rte_rwlock_init(&arr->rwlock);

	rte_spinlock_unlock(&mem_area_lock);

	return 0;
fail:
	if (data)
		rte_mem_unmap(data, mmap_len);
	if (fd >= 0)
		close(fd);
	free(ma);

	rte_spinlock_unlock(&mem_area_lock);
	return -1;
}

RTE_EXPORT_SYMBOL(rte_fbarray_attach)
int
rte_fbarray_attach(struct rte_fbarray *arr)
{
	struct mem_area *ma = NULL, *tmp = NULL;
	size_t page_sz, mmap_len;
	char path[PATH_MAX];
	void *data = NULL;
	int fd = -1;

	if (arr == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	/*
	 * we don't need to synchronize attach as two values we need (element
	 * size and array length) are constant for the duration of life of
	 * the array, so the parts we care about will not race.
	 */

	if (fully_validate(arr->name, arr->elt_sz, arr->len))
		return -1;

	ma = malloc(sizeof(*ma));
	if (ma == NULL) {
		rte_errno = ENOMEM;
		return -1;
	}

	page_sz = rte_mem_page_size();
	if (page_sz == (size_t)-1) {
		free(ma);
		return -1;
	}

	mmap_len = calc_data_size(page_sz, arr->elt_sz, arr->len);

	/* check the tailq - maybe user has already mapped this address space */
	rte_spinlock_lock(&mem_area_lock);

	TAILQ_FOREACH(tmp, &mem_area_tailq, next) {
		if (overlap(tmp, arr->data, mmap_len)) {
			rte_errno = EEXIST;
			goto fail;
		}
	}

	/* we know this memory area is unique, so proceed */

	data = eal_get_virtual_area(arr->data, &mmap_len, page_sz, 0, 0);
	if (data == NULL)
		goto fail;

	eal_get_fbarray_path(path, sizeof(path), arr->name);

	fd = eal_file_open(path, EAL_OPEN_READWRITE);
	if (fd < 0) {
		goto fail;
	}

	/* lock the file, to let others know we're using it */
	if (eal_file_lock(fd, EAL_FLOCK_SHARED, EAL_FLOCK_RETURN))
		goto fail;

	if (resize_and_map(fd, path, data, mmap_len))
		goto fail;

	/* store our new memory area */
	ma->addr = data;
	ma->fd = fd; /* keep fd until detach/destroy */
	ma->len = mmap_len;

	TAILQ_INSERT_TAIL(&mem_area_tailq, ma, next);

	/* we're done */

	rte_spinlock_unlock(&mem_area_lock);
	return 0;
fail:
	if (data)
		rte_mem_unmap(data, mmap_len);
	if (fd >= 0)
		close(fd);
	free(ma);
	rte_spinlock_unlock(&mem_area_lock);
	return -1;
}

RTE_EXPORT_SYMBOL(rte_fbarray_detach)
int
rte_fbarray_detach(struct rte_fbarray *arr)
{
	struct mem_area *tmp = NULL;
	size_t mmap_len;
	int ret = -1;

	if (arr == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	/*
	 * we don't need to synchronize detach as two values we need (element
	 * size and total capacity) are constant for the duration of life of
	 * the array, so the parts we care about will not race. if the user is
	 * detaching while doing something else in the same process, we can't
	 * really do anything about it, things will blow up either way.
	 */

	size_t page_sz = rte_mem_page_size();
	if (page_sz == (size_t)-1)
		return -1;

	mmap_len = calc_data_size(page_sz, arr->elt_sz, arr->len);

	/* does this area exist? */
	rte_spinlock_lock(&mem_area_lock);

	TAILQ_FOREACH(tmp, &mem_area_tailq, next) {
		if (tmp->addr == arr->data && tmp->len == mmap_len)
			break;
	}
	if (tmp == NULL) {
		rte_errno = ENOENT;
		ret = -1;
		goto out;
	}

	rte_mem_unmap(arr->data, mmap_len);

	/* area is unmapped, close fd and remove the tailq entry */
	if (tmp->fd >= 0)
		close(tmp->fd);
	TAILQ_REMOVE(&mem_area_tailq, tmp, next);
	free(tmp);

	ret = 0;
out:
	rte_spinlock_unlock(&mem_area_lock);
	return ret;
}

RTE_EXPORT_SYMBOL(rte_fbarray_destroy)
int
rte_fbarray_destroy(struct rte_fbarray *arr)
{
	struct mem_area *tmp = NULL;
	size_t mmap_len;
	int fd, ret;
	char path[PATH_MAX];
	const struct internal_config *internal_conf =
		eal_get_internal_configuration();

	if (arr == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	/*
	 * we don't need to synchronize detach as two values we need (element
	 * size and total capacity) are constant for the duration of life of
	 * the array, so the parts we care about will not race. if the user is
	 * detaching while doing something else in the same process, we can't
	 * really do anything about it, things will blow up either way.
	 */

	size_t page_sz = rte_mem_page_size();
	if (page_sz == (size_t)-1)
		return -1;

	mmap_len = calc_data_size(page_sz, arr->elt_sz, arr->len);

	/* does this area exist? */
	rte_spinlock_lock(&mem_area_lock);

	TAILQ_FOREACH(tmp, &mem_area_tailq, next) {
		if (tmp->addr == arr->data && tmp->len == mmap_len)
			break;
	}
	if (tmp == NULL) {
		rte_errno = ENOENT;
		ret = -1;
		goto out;
	}
	/* with no shconf, there were never any files to begin with */
	if (!internal_conf->no_shconf) {
		/*
		 * attempt to get an exclusive lock on the file, to ensure it
		 * has been detached by all other processes
		 */
		fd = tmp->fd;
		if (eal_file_lock(fd, EAL_FLOCK_EXCLUSIVE, EAL_FLOCK_RETURN)) {
			EAL_LOG(DEBUG, "Cannot destroy fbarray - another process is using it");
			rte_errno = EBUSY;
			ret = -1;
			goto out;
		}

		/* we're OK to destroy the file */
		eal_get_fbarray_path(path, sizeof(path), arr->name);
		if (unlink(path)) {
			EAL_LOG(DEBUG, "Cannot unlink fbarray: %s",
				strerror(errno));
			rte_errno = errno;
			/*
			 * we're still holding an exclusive lock, so drop it to
			 * shared.
			 */
			eal_file_lock(fd, EAL_FLOCK_SHARED, EAL_FLOCK_RETURN);

			ret = -1;
			goto out;
		}
		close(fd);
	}
	rte_mem_unmap(arr->data, mmap_len);

	/* area is unmapped, remove the tailq entry */
	TAILQ_REMOVE(&mem_area_tailq, tmp, next);
	free(tmp);
	ret = 0;

	/* reset the fbarray structure */
	memset(arr, 0, sizeof(*arr));
out:
	rte_spinlock_unlock(&mem_area_lock);
	return ret;
}

RTE_EXPORT_SYMBOL(rte_fbarray_get)
void *
rte_fbarray_get(const struct rte_fbarray *arr, unsigned int idx)
{
	void *ret = NULL;
	if (arr == NULL) {
		rte_errno = EINVAL;
		return NULL;
	}

	if (idx >= arr->len) {
		rte_errno = EINVAL;
		return NULL;
	}

	ret = RTE_PTR_ADD(arr->data, idx * arr->elt_sz);

	return ret;
}

RTE_EXPORT_SYMBOL(rte_fbarray_set_used)
int
rte_fbarray_set_used(struct rte_fbarray *arr, unsigned int idx)
{
	return set_used(arr, idx, true);
}

RTE_EXPORT_SYMBOL(rte_fbarray_set_free)
int
rte_fbarray_set_free(struct rte_fbarray *arr, unsigned int idx)
{
	return set_used(arr, idx, false);
}

RTE_EXPORT_SYMBOL(rte_fbarray_is_used)
int
rte_fbarray_is_used(struct rte_fbarray *arr, unsigned int idx)
{
	struct used_mask *msk;
	int msk_idx;
	uint64_t msk_bit;
	int ret = -1;

	if (arr == NULL || idx >= arr->len) {
		rte_errno = EINVAL;
		return -1;
	}

	/* prevent array from changing under us */
	rte_rwlock_read_lock(&arr->rwlock);

	msk = get_used_mask(arr->data, arr->elt_sz, arr->len);
	msk_idx = MASK_LEN_TO_IDX(idx);
	msk_bit = 1ULL << MASK_LEN_TO_MOD(idx);

	ret = (msk->data[msk_idx] & msk_bit) != 0;

	rte_rwlock_read_unlock(&arr->rwlock);

	return ret;
}

static int
fbarray_find(struct rte_fbarray *arr, unsigned int start, bool next, bool used)
{
	int ret = -1;

	if (arr == NULL || start >= arr->len) {
		rte_errno = EINVAL;
		return -1;
	}

	/* prevent array from changing under us */
	rte_rwlock_read_lock(&arr->rwlock);

	/* cheap checks to prevent doing useless work */
	if (!used) {
		if (arr->len == arr->count) {
			rte_errno = ENOSPC;
			goto out;
		}
		if (arr->count == 0) {
			ret = start;
			goto out;
		}
	} else {
		if (arr->count == 0) {
			rte_errno = ENOENT;
			goto out;
		}
		if (arr->len == arr->count) {
			ret = start;
			goto out;
		}
	}
	if (next)
		ret = find_next(arr, start, used);
	else
		ret = find_prev(arr, start, used);
out:
	rte_rwlock_read_unlock(&arr->rwlock);
	return ret;
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_next_free)
int
rte_fbarray_find_next_free(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find(arr, start, true, false);
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_next_used)
int
rte_fbarray_find_next_used(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find(arr, start, true, true);
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_prev_free)
int
rte_fbarray_find_prev_free(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find(arr, start, false, false);
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_prev_used)
int
rte_fbarray_find_prev_used(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find(arr, start, false, true);
}

static int
fbarray_find_n(struct rte_fbarray *arr, unsigned int start, unsigned int n,
		bool next, bool used)
{
	int ret = -1;

	if (arr == NULL || start >= arr->len || n > arr->len || n == 0) {
		rte_errno = EINVAL;
		return -1;
	}
	if (next && (arr->len - start) < n) {
		rte_errno = used ? ENOENT : ENOSPC;
		return -1;
	}
	if (!next && start < (n - 1)) {
		rte_errno = used ? ENOENT : ENOSPC;
		return -1;
	}

	/* prevent array from changing under us */
	rte_rwlock_read_lock(&arr->rwlock);

	/* cheap checks to prevent doing useless work */
	if (!used) {
		if (arr->len == arr->count || arr->len - arr->count < n) {
			rte_errno = ENOSPC;
			goto out;
		}
		if (arr->count == 0) {
			ret = next ? start : start - n + 1;
			goto out;
		}
	} else {
		if (arr->count < n) {
			rte_errno = ENOENT;
			goto out;
		}
		if (arr->count == arr->len) {
			ret = next ? start : start - n + 1;
			goto out;
		}
	}

	if (next)
		ret = find_next_n(arr, start, n, used);
	else
		ret = find_prev_n(arr, start, n, used);
out:
	rte_rwlock_read_unlock(&arr->rwlock);
	return ret;
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_next_n_free)
int
rte_fbarray_find_next_n_free(struct rte_fbarray *arr, unsigned int start,
		unsigned int n)
{
	return fbarray_find_n(arr, start, n, true, false);
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_next_n_used)
int
rte_fbarray_find_next_n_used(struct rte_fbarray *arr, unsigned int start,
		unsigned int n)
{
	return fbarray_find_n(arr, start, n, true, true);
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_prev_n_free)
int
rte_fbarray_find_prev_n_free(struct rte_fbarray *arr, unsigned int start,
		unsigned int n)
{
	return fbarray_find_n(arr, start, n, false, false);
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_prev_n_used)
int
rte_fbarray_find_prev_n_used(struct rte_fbarray *arr, unsigned int start,
		unsigned int n)
{
	return fbarray_find_n(arr, start, n, false, true);
}

static int
fbarray_find_contig(struct rte_fbarray *arr, unsigned int start, bool next,
		bool used)
{
	int ret = -1;

	if (arr == NULL || start >= arr->len) {
		rte_errno = EINVAL;
		return -1;
	}

	/* prevent array from changing under us */
	rte_rwlock_read_lock(&arr->rwlock);

	/* cheap checks to prevent doing useless work */
	if (used) {
		if (arr->count == 0) {
			ret = 0;
			goto out;
		}
		if (next && arr->count == arr->len) {
			ret = arr->len - start;
			goto out;
		}
		if (!next && arr->count == arr->len) {
			ret = start + 1;
			goto out;
		}
	} else {
		if (arr->len == arr->count) {
			ret = 0;
			goto out;
		}
		if (next && arr->count == 0) {
			ret = arr->len - start;
			goto out;
		}
		if (!next && arr->count == 0) {
			ret = start + 1;
			goto out;
		}
	}

	if (next)
		ret = find_contig(arr, start, used);
	else
		ret = find_rev_contig(arr, start, used);
out:
	rte_rwlock_read_unlock(&arr->rwlock);
	return ret;
}

static int
fbarray_find_biggest(struct rte_fbarray *arr, unsigned int start, bool used,
		bool rev)
{
	int cur_idx, next_idx, cur_len, biggest_idx, biggest_len;
	/* don't stack if conditions, use function pointers instead */
	int (*find_func)(struct rte_fbarray *, unsigned int);
	int (*find_contig_func)(struct rte_fbarray *, unsigned int);

	if (arr == NULL || start >= arr->len) {
		rte_errno = EINVAL;
		return -1;
	}
	/* the other API calls already do their fair share of cheap checks, so
	 * no need to do them here.
	 */

	/* the API's called are thread-safe, but something may still happen
	 * between the API calls, so lock the fbarray. all other API's are
	 * read-locking the fbarray, so read lock here is OK.
	 */
	rte_rwlock_read_lock(&arr->rwlock);

	/* pick out appropriate functions */
	if (used) {
		if (rev) {
			find_func = rte_fbarray_find_prev_used;
			find_contig_func = rte_fbarray_find_rev_contig_used;
		} else {
			find_func = rte_fbarray_find_next_used;
			find_contig_func = rte_fbarray_find_contig_used;
		}
	} else {
		if (rev) {
			find_func = rte_fbarray_find_prev_free;
			find_contig_func = rte_fbarray_find_rev_contig_free;
		} else {
			find_func = rte_fbarray_find_next_free;
			find_contig_func = rte_fbarray_find_contig_free;
		}
	}

	cur_idx = start;
	biggest_idx = -1; /* default is error */
	biggest_len = 0;
	for (;;) {
		cur_idx = find_func(arr, cur_idx);

		/* block found, check its length */
		if (cur_idx >= 0) {
			cur_len = find_contig_func(arr, cur_idx);
			/* decide where we go next */
			next_idx = rev ? cur_idx - cur_len : cur_idx + cur_len;
			/* move current index to start of chunk */
			cur_idx = rev ? next_idx + 1 : cur_idx;

			if (cur_len > biggest_len) {
				biggest_idx = cur_idx;
				biggest_len = cur_len;
			}
			cur_idx = next_idx;
			/* in reverse mode, next_idx may be -1 if chunk started
			 * at array beginning. this means there's no more work
			 * to do.
			 */
			if (cur_idx < 0)
				break;
		} else {
			/* nothing more to find, stop. however, a failed API
			 * call has set rte_errno, which we want to ignore, as
			 * reaching the end of fbarray is not an error.
			 */
			rte_errno = 0;
			break;
		}
	}
	/* if we didn't find anything at all, set rte_errno */
	if (biggest_idx < 0)
		rte_errno = used ? ENOENT : ENOSPC;

	rte_rwlock_read_unlock(&arr->rwlock);
	return biggest_idx;
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_biggest_free)
int
rte_fbarray_find_biggest_free(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find_biggest(arr, start, false, false);
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_biggest_used)
int
rte_fbarray_find_biggest_used(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find_biggest(arr, start, true, false);
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_rev_biggest_free)
int
rte_fbarray_find_rev_biggest_free(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find_biggest(arr, start, false, true);
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_rev_biggest_used)
int
rte_fbarray_find_rev_biggest_used(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find_biggest(arr, start, true, true);
}


RTE_EXPORT_SYMBOL(rte_fbarray_find_contig_free)
int
rte_fbarray_find_contig_free(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find_contig(arr, start, true, false);
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_contig_used)
int
rte_fbarray_find_contig_used(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find_contig(arr, start, true, true);
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_rev_contig_free)
int
rte_fbarray_find_rev_contig_free(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find_contig(arr, start, false, false);
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_rev_contig_used)
int
rte_fbarray_find_rev_contig_used(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find_contig(arr, start, false, true);
}

RTE_EXPORT_SYMBOL(rte_fbarray_find_idx)
int
rte_fbarray_find_idx(const struct rte_fbarray *arr, const void *elt)
{
	void *end;
	int ret = -1;

	/*
	 * no need to synchronize as it doesn't matter if underlying data
	 * changes - we're doing pointer arithmetic here.
	 */

	if (arr == NULL || elt == NULL) {
		rte_errno = EINVAL;
		return -1;
	}
	end = RTE_PTR_ADD(arr->data, arr->elt_sz * arr->len);
	if (elt < arr->data || elt >= end) {
		rte_errno = EINVAL;
		return -1;
	}

	ret = RTE_PTR_DIFF(elt, arr->data) / arr->elt_sz;

	return ret;
}

RTE_EXPORT_SYMBOL(rte_fbarray_dump_metadata)
void
rte_fbarray_dump_metadata(struct rte_fbarray *arr, FILE *f)
{
	struct used_mask *msk;
	unsigned int i;

	if (arr == NULL || f == NULL) {
		rte_errno = EINVAL;
		return;
	}

	if (fully_validate(arr->name, arr->elt_sz, arr->len)) {
		fprintf(f, "Invalid file-backed array\n");
		return;
	}

	/* prevent array from changing under us */
	rte_rwlock_read_lock(&arr->rwlock);

	fprintf(f, "File-backed array: %s\n", arr->name);
	fprintf(f, "size: %i occupied: %i elt_sz: %i\n",
			arr->len, arr->count, arr->elt_sz);

	msk = get_used_mask(arr->data, arr->elt_sz, arr->len);

	for (i = 0; i < msk->n_masks; i++)
		fprintf(f, "msk idx %i: 0x%016" PRIx64 "\n", i, msk->data[i]);
	rte_rwlock_read_unlock(&arr->rwlock);
}
