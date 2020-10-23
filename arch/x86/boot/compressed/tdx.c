// SPDX-License-Identifier: GPL-2.0

#include "../cpuflags.h"
#include "../string.h"
#include "../io.h"
#include "error.h"

#include <vdso/limits.h>
#include <uapi/asm/vmx.h>

#include <asm/shared/tdx.h>
#include <asm/page_types.h>

/* Called from __tdx_hypercall() for unrecoverable failure */
void __tdx_hypercall_failed(void)
{
	error("TDVMCALL failed. TDX module bug?");
}

static inline unsigned int tdx_io_in(int size, u16 port)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_IO_INSTRUCTION,
		.r12 = size,
		.r13 = 0,
		.r14 = port,
	};

	if (__tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT))
		return UINT_MAX;

	return args.r11;
}

static inline void tdx_io_out(int size, u16 port, u32 value)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_IO_INSTRUCTION,
		.r12 = size,
		.r13 = 1,
		.r14 = port,
		.r15 = value,
	};

	__tdx_hypercall(&args, 0);
}

static inline u8 tdx_inb(u16 port)
{
	return tdx_io_in(1, port);
}

static inline void tdx_outb(u8 value, u16 port)
{
	tdx_io_out(1, port, value);
}

static inline void tdx_outw(u16 value, u16 port)
{
	tdx_io_out(2, port, value);
}

static int tdx_guest = -1;
int cmdline_find_option_bool(const char *option);

void early_tdx_detect(void)
{
	u32 eax, sig[3];

	if (!cmdline_find_option_bool("force_tdx_guest")) {
		cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax,
			    &sig[0], &sig[2],  &sig[1]);

		if (memcmp(TDX_IDENT, sig, sizeof(sig)))
			return;
	}

	/* Use hypercalls instead of I/O instructions */
	pio_ops.f_inb  = tdx_inb;
	pio_ops.f_outb = tdx_outb;
	pio_ops.f_outw = tdx_outw;

	tdx_guest = 1;
}

bool early_is_tdx_guest(void)
{
	if (tdx_guest < 0)
		early_tdx_detect();

	return !!tdx_guest;
}

#define TDACCEPTPAGE		6
#define TDVMCALL_MAP_GPA	0x10001

void tdx_accept_memory(phys_addr_t start, phys_addr_t end)
{
	int i;
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = TDVMCALL_MAP_GPA,
		.r12 = start,
		.r13 = end - start,
		.r14 = 0,
		.r15 = 0,
	};

	if (__tdx_hypercall(&args, 0)) {
		error("Cannot accept memory: MapGPA failed\n");
	}

	/*
	 * For shared->private conversion, accept the page using TDACCEPTPAGE
	 * TDX module call.
	 */
	for (i = 0; i < (end - start) / PAGE_SIZE; i++) {
		if (__tdx_module_call(TDACCEPTPAGE, start + i * PAGE_SIZE,
				      0, 0, 0, NULL)) {
			error("Cannot accept memory: page accept failed\n");
		}
	}
}
