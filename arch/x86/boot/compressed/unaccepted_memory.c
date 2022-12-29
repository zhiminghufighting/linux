// SPDX-License-Identifier: GPL-2.0-only

#include <asm/shared/tdx.h>
#include "error.h"
#include "misc.h"
#include "tdx.h"

#ifdef CONFIG_INTEL_TDX_GUEST
extern bool early_is_tdx_guest(void);
#else
static bool early_is_tdx_guest(void) { return false; }
#endif

static inline void __accept_memory(phys_addr_t start, phys_addr_t end)
{
	/* Platform-specific memory-acceptance call goes here */
	if (early_is_tdx_guest())
		tdx_accept_memory(start, end);
	else
		error("Cannot accept memory");
}

void mark_unaccepted(struct boot_params *params, u64 start, u64 end)
{
	/*
	 * The accepted memory bitmap only works at PMD_SIZE granularity.
	 * If a request comes in to mark memory as unaccepted which is not
	 * PMD_SIZE-aligned, simply accept the memory now since it can not be
	 * *marked* as unaccepted.
	 */

	/* __accept_memory() needs to know if kernel runs in TDX environment */
	early_tdx_detect();

	/* Immediately accept whole range if it is within a PMD_SIZE block: */
	if ((start & PMD_MASK) == (end & PMD_MASK)) {
		__accept_memory(start, end);
		return;
	}

	/* Immediately accept a <PMD_SIZE piece at the start: */
	if (start & ~PMD_MASK) {
		__accept_memory(start, round_up(start, PMD_SIZE));
		start = round_up(start, PMD_SIZE);
	}

	/* Immediately accept a <PMD_SIZE piece at the end: */
	if (end & ~PMD_MASK) {
		__accept_memory(round_down(end, PMD_SIZE), end);
		end = round_down(end, PMD_SIZE);
	}

	if (start == end)
		return;

	bitmap_set((unsigned long *)params->unaccepted_memory,
		   start / PMD_SIZE, (end - start) / PMD_SIZE);
}

void accept_memory(phys_addr_t start, phys_addr_t end)
{
	unsigned long *unaccepted_memory;
	unsigned int rs, re;

	unaccepted_memory = (unsigned long *)boot_params->unaccepted_memory;
	rs = start / PMD_SIZE;
	for_each_set_bitrange_from(rs, re, unaccepted_memory,
				   DIV_ROUND_UP(end, PMD_SIZE)) {
		__accept_memory(rs * PMD_SIZE, re * PMD_SIZE);
		bitmap_clear(unaccepted_memory, rs, re - rs);
	}
}
