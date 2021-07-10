// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2022 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "tdx: " fmt

#include <linux/cpufeature.h>
#include <asm/coco.h>
#include <asm/tdx.h>
#include <asm/cmdline.h>
#include <asm/i8259.h>
#include <asm/apic.h>
#include <asm/idtentry.h>
#include <asm/irq_regs.h>
#include <asm/desc.h>
#include <asm/vmx.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <asm/pgtable.h>
#include <linux/pci.h>
#include <linux/nmi.h>
#include <linux/random.h>

#define CREATE_TRACE_POINTS
#include <asm/trace/tdx.h>

/* TDX module Call Leaf IDs */
#define TDX_GET_INFO			1
#define TDX_RMTR_EXTEND			2
#define TDX_GET_VEINFO			3
#define TDX_GET_REPORT			4
#define TDX_ACCEPT_PAGE			6

/* TDX hypercall Leaf IDs */
#define TDVMCALL_MAP_GPA		0x10001
#define TDVMCALL_GET_QUOTE		0x10002
#define TDVMCALL_SETUP_NOTIFY_INTR	0x10004

/* MMIO direction */
#define EPT_READ	0
#define EPT_WRITE	1

/* Port I/O direction */
#define PORT_READ	0
#define PORT_WRITE	1

/* See Exit Qualification for I/O Instructions in VMX documentation */
#define VE_IS_IO_IN(e)		((e) & BIT(3))
#define VE_GET_IO_SIZE(e)	(((e) & GENMASK(2, 0)) + 1)
#define VE_GET_PORT_NUM(e)	((e) >> 16)
#define VE_IS_IO_STRING(e)	((e) & BIT(4))

/* TDX Module call error codes */
#define TDCALL_RETURN_CODE_MASK		0xffffffff00000000
#define TDCALL_RETURN_CODE(a)		((a) & TDCALL_RETURN_CODE_MASK)
#define TDCALL_SUCCESS			0x0
#define TDCALL_INVALID_OPERAND		0x8000000000000000
#define TDCALL_OPERAND_BUSY		0x8000020000000000

/* TDX hypercall error codes */
#define TDVMCALL_SUCCESS		0x0
#define TDVMCALL_INVALID_OPERAND	0x8000000000000000
#define TDVMCALL_GPA_IN_USE		0x8000000000000001

/*
 * Currently it will be used only by the attestation
 * driver. So, race condition with read/write operation
 * is not considered.
 */
void (*tdx_event_notify_handler)(void);
EXPORT_SYMBOL_GPL(tdx_event_notify_handler);

/*
 * Wrapper for standard use of __tdx_hypercall with no output aside from
 * return code.
 */
static inline u64 _tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = fn,
		.r12 = r12,
		.r13 = r13,
		.r14 = r14,
		.r15 = r15,
	};

	return __tdx_hypercall(&args, 0);
}

/* Called from __tdx_hypercall() for unrecoverable failure */
void __tdx_hypercall_failed(void)
{
	panic("TDVMCALL failed. TDX module bug?");
}

/*
 * The TDG.VP.VMCALL-Instruction-execution sub-functions are defined
 * independently from but are currently matched 1:1 with VMX EXIT_REASONs.
 * Reusing the KVM EXIT_REASON macros makes it easier to connect the host and
 * guest sides of these calls.
 */
static u64 hcall_func(u64 exit_reason)
{
	return exit_reason;
}

#ifdef CONFIG_KVM_GUEST
long tdx_kvm_hypercall(unsigned int nr, unsigned long p1, unsigned long p2,
		       unsigned long p3, unsigned long p4)
{
	struct tdx_hypercall_args args = {
		.r10 = nr,
		.r11 = p1,
		.r12 = p2,
		.r13 = p3,
		.r14 = p4,
	};

	return __tdx_hypercall(&args, 0);
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall);
#endif

/* TDX guest event notification handler */
DEFINE_IDTENTRY_SYSVEC(sysvec_tdx_event_notify)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	inc_irq_stat(irq_tdx_event_notify_count);

	if (tdx_event_notify_handler)
		tdx_event_notify_handler();

	/*
	 * The hypervisor requires that the APIC EOI should be acked.
	 * If the APIC EOI is not acked, the APIC ISR bit for the
	 * TDX_GUEST_EVENT_NOTIFY_VECTOR will not be cleared and then it
	 * will block the interrupt whose vector is lower than
	 * TDX_GUEST_EVENT_NOTIFY_VECTOR.
	 */
	ack_APIC_irq();

	set_irq_regs(old_regs);
}

/*
 * Used for TDX guests to make calls directly to the TD module.  This
 * should only be used for calls that have no legitimate reason to fail
 * or where the kernel can not survive the call failing.
 */
static inline void tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
				   struct tdx_module_output *out)
{
	if (__tdx_module_call(fn, rcx, rdx, r8, r9, out))
		panic("TDCALL %lld failed (Buggy TDX module!)\n", fn);
}

/*
 * tdx_mcall_tdreport() - Generate TDREPORT_STRUCT using TDCALL.
 *
 * @data        : Physical address of 1024B aligned data to store
 *                TDREPORT_STRUCT.
 * @reportdata  : Physical address of 64B aligned report data
 *
 * return 0 on success or failure error number.
 */
int tdx_mcall_tdreport(u64 data, u64 reportdata)
{
	u64 ret;

	/*
	 * Use confidential guest TDX check to ensure this API is only
	 * used by TDX guest platforms.
	 */
	if (!data || !reportdata || !cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return -EINVAL;

	/*
	 * Pass the physical address of user generated reportdata
	 * and the physical address of out pointer to store the
	 * tdreport data to the TDX module to generate the
	 * TD report. Generated data contains measurements/configuration
	 * data of the TD guest. More info about ABI can be found in TDX
	 * Guest-Host-Communication Interface (GHCI), sec 2.4.5.
	 */
	ret = __tdx_module_call(TDX_GET_REPORT, data, reportdata, 0, 0,
				NULL);

	if (ret == TDCALL_SUCCESS)
		return 0;
	else if (TDCALL_RETURN_CODE(ret) == TDCALL_INVALID_OPERAND)
		return -EINVAL;
	else if (TDCALL_RETURN_CODE(ret) == TDCALL_OPERAND_BUSY)
		return -EBUSY;

	return -EIO;
}
EXPORT_SYMBOL_GPL(tdx_mcall_tdreport);

/*
 * tdx_mcall_rtmr_extend() - Extend a TDX measurement register
 *
 * @data	: Physical address of 96B aligned data.
 * @rtmr	: RTMR number
 *
 * return 0 on success or failure error number.
 */
int tdx_mcall_rtmr_extend(u64 data, u64 rtmr)
{
	u64 ret;

	if (!data || !cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return -EINVAL;

	ret = __tdx_module_call(TDX_RMTR_EXTEND, data, rtmr, 0, 0, NULL);

	if (ret == TDCALL_SUCCESS)
		return 0;
	else if (TDCALL_RETURN_CODE(ret) == TDCALL_INVALID_OPERAND)
		return -EINVAL;
	else if (TDCALL_RETURN_CODE(ret) == TDCALL_OPERAND_BUSY)
		return -EBUSY;

	return -EIO;
}
EXPORT_SYMBOL_GPL(tdx_mcall_rtmr_extend);

/*
 * tdx_hcall_get_quote() - Generate TDQUOTE using TDREPORT_STRUCT.
 *
 * @data        : Physical address of 4KB GPA memory which contains
 *                TDREPORT_STRUCT.
 *
 * return 0 on success or failure error number.
 */
int tdx_hcall_get_quote(u64 data)
{
	u64 ret;

	/*
	 * Use confidential guest TDX check to ensure this API is only
	 * used by TDX guest platforms.
	 */
	if (!data || !cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return -EINVAL;

	/*
	 * Pass the physical address of tdreport data to the VMM
	 * and trigger the tdquote generation. Quote data will be
	 * stored back in the same physical address space. More info
	 * about ABI can be found in TDX Guest-Host-Communication
	 * Interface (GHCI), sec 3.3.
	 */
	ret = _tdx_hypercall(TDVMCALL_GET_QUOTE, data, 0, 0, 0);

	if (ret == TDVMCALL_SUCCESS)
		return 0;
	else if (ret == TDVMCALL_INVALID_OPERAND)
		return -EINVAL;
	else if (ret == TDVMCALL_GPA_IN_USE)
		return -EBUSY;

	return -EIO;
}
EXPORT_SYMBOL_GPL(tdx_hcall_get_quote);

/*
 * tdx_hcall_set_notify_intr() - Setup Event Notify Interrupt Vector.
 *
 * @vector        : Vector address to be used for notification.
 *
 * return 0 on success or failure error number.
 */
static int tdx_hcall_set_notify_intr(u8 vector)
{
	u64 ret;

	/* Minimum vector value allowed is 32 */
	if (vector < 32)
		return -EINVAL;

	/*
	 * Register callback vector address with VMM. More details
	 * about the ABI can be found in TDX Guest-Host-Communication
	 * Interface (GHCI), sec 3.5.
	 */
	ret = _tdx_hypercall(TDVMCALL_SETUP_NOTIFY_INTR, vector, 0, 0, 0);

	if (ret == TDVMCALL_SUCCESS)
		return 0;
	else if (ret == TDCALL_INVALID_OPERAND)
		return -EINVAL;

	return -EIO;
}

static u64 get_cc_mask(void)
{
	struct tdx_module_output out;
	unsigned int gpa_width;

	/*
	 * TDINFO TDX module call is used to get the TD execution environment
	 * information like GPA width, number of available vcpus, debug mode
	 * information, etc. More details about the ABI can be found in TDX
	 * Guest-Host-Communication Interface (GHCI), section 2.4.2 TDCALL
	 * [TDG.VP.INFO].
	 *
	 * The GPA width that comes out of this call is critical. TDX guests
	 * can not meaningfully run without it.
	 */
	tdx_module_call(TDX_GET_INFO, 0, 0, 0, 0, &out);

	gpa_width = out.rcx & GENMASK(5, 0);

	/*
	 * The highest bit of a guest physical address is the "sharing" bit.
	 * Set it for shared pages and clear it for private pages.
	 */
	return BIT_ULL(gpa_width - 1);
}

/*
 * The TDX module spec states that #VE may be injected for a limited set of
 * reasons:
 *
 *  - Emulation of the architectural #VE injection on EPT violation;
 *
 *  - As a result of guest TD execution of a disallowed instruction,
 *    a disallowed MSR access, or CPUID virtualization;
 *
 *  - A notification to the guest TD about anomalous behavior;
 *
 * The last one is opt-in and is not used by the kernel.
 *
 * The Intel Software Developer's Manual describes cases when instruction
 * length field can be used in section "Information for VM Exits Due to
 * Instruction Execution".
 *
 * For TDX, it ultimately means GET_VEINFO provides reliable instruction length
 * information if #VE occurred due to instruction execution, but not for EPT
 * violations.
 */
static int ve_instr_len(struct ve_info *ve)
{
	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
	case EXIT_REASON_MSR_READ:
	case EXIT_REASON_MSR_WRITE:
	case EXIT_REASON_CPUID:
	case EXIT_REASON_IO_INSTRUCTION:
		/* It is safe to use ve->instr_len for #VE due instructions */
		return ve->instr_len;
	case EXIT_REASON_EPT_VIOLATION:
		/*
		 * For EPT violations, ve->insn_len is not defined. For those,
		 * the kernel must decode instructions manually and should not
		 * be using this function.
		 */
		WARN_ONCE(1, "ve->instr_len is not defined for EPT violations");
		return 0;
	default:
		WARN_ONCE(1, "Unexpected #VE-type: %lld\n", ve->exit_reason);
		return ve->instr_len;
	}
}

static u64 __cpuidle __halt(const bool irq_disabled, const bool do_sti)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_HLT),
		.r12 = irq_disabled,
	};

	/*
	 * Emulate HLT operation via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section 3.8 TDG.VP.VMCALL<Instruction.HLT>.
	 *
	 * The VMM uses the "IRQ disabled" param to understand IRQ
	 * enabled status (RFLAGS.IF) of the TD guest and to determine
	 * whether or not it should schedule the halted vCPU if an
	 * IRQ becomes pending. E.g. if IRQs are disabled, the VMM
	 * can keep the vCPU in virtual HLT, even if an IRQ is
	 * pending, without hanging/breaking the guest.
	 */
	return __tdx_hypercall(&args, do_sti ? TDX_HCALL_ISSUE_STI : 0);
}

static int handle_halt(struct ve_info *ve)
{
	/*
	 * Since non safe halt is mainly used in CPU offlining
	 * and the guest will always stay in the halt state, don't
	 * call the STI instruction (set do_sti as false).
	 */
	const bool irq_disabled = irqs_disabled();
	const bool do_sti = false;

	if (__halt(irq_disabled, do_sti))
		return -EIO;

	return ve_instr_len(ve);
}

void __cpuidle tdx_safe_halt(void)
{
	 /*
	  * For do_sti=true case, __tdx_hypercall() function enables
	  * interrupts using the STI instruction before the TDCALL. So
	  * set irq_disabled as false.
	  */
	const bool irq_disabled = false;
	const bool do_sti = true;

	/*
	 * Use WARN_ONCE() to report the failure.
	 */
	if (__halt(irq_disabled, do_sti))
		WARN_ONCE(1, "HLT instruction emulation failed\n");
}

static int read_msr(struct pt_regs *regs, struct ve_info *ve)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_MSR_READ),
		.r12 = regs->cx,
	};

	/*
	 * Emulate the MSR read via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "TDG.VP.VMCALL<Instruction.RDMSR>".
	 */
	if (__tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT))
		return -EIO;

	regs->ax = lower_32_bits(args.r11);
	regs->dx = upper_32_bits(args.r11);
	return ve_instr_len(ve);
}

static int write_msr(struct pt_regs *regs, struct ve_info *ve)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_MSR_WRITE),
		.r12 = regs->cx,
		.r13 = (u64)regs->dx << 32 | regs->ax,
	};

	/*
	 * Emulate the MSR write via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI) section titled "TDG.VP.VMCALL<Instruction.WRMSR>".
	 */
	if (__tdx_hypercall(&args, 0))
		return -EIO;

	return ve_instr_len(ve);
}

static int handle_cpuid(struct pt_regs *regs, struct ve_info *ve)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_CPUID),
		.r12 = regs->ax,
		.r13 = regs->cx,
	};

	/*
	 * Only allow VMM to control range reserved for hypervisor
	 * communication.
	 *
	 * Return all-zeros for any CPUID outside the range. It matches CPU
	 * behaviour for non-supported leaf.
	 */
	if (regs->ax < 0x40000000 || regs->ax > 0x4FFFFFFF) {
		regs->ax = regs->bx = regs->cx = regs->dx = 0;
		return ve_instr_len(ve);
	}

	/*
	 * Emulate the CPUID instruction via a hypercall. More info about
	 * ABI can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "VP.VMCALL<Instruction.CPUID>".
	 */
	if (__tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT))
		return -EIO;

	/*
	 * As per TDX GHCI CPUID ABI, r12-r15 registers contain contents of
	 * EAX, EBX, ECX, EDX registers after the CPUID instruction execution.
	 * So copy the register contents back to pt_regs.
	 */
	regs->ax = args.r12;
	regs->bx = args.r13;
	regs->cx = args.r14;
	regs->dx = args.r15;

	return ve_instr_len(ve);
}

static bool mmio_read(int size, unsigned long addr, unsigned long *val)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_EPT_VIOLATION),
		.r12 = size,
		.r13 = EPT_READ,
		.r14 = addr,
		.r15 = *val,
	};

	if (__tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT))
		return false;
	*val = args.r11;
	return true;
}

static bool mmio_write(int size, unsigned long addr, unsigned long val)
{
	return !_tdx_hypercall(hcall_func(EXIT_REASON_EPT_VIOLATION), size,
			       EPT_WRITE, addr, val);
}

static int handle_mmio(struct pt_regs *regs, struct ve_info *ve)
{
	unsigned long *reg, val, vaddr;
	char buffer[MAX_INSN_SIZE];
	struct insn insn = {};
	enum mmio_type mmio;
	int size, extend_size;
	u8 extend_val = 0;

	/* Only in-kernel MMIO is supported */
	if (WARN_ON_ONCE(user_mode(regs)))
		return -EFAULT;

	if (copy_from_kernel_nofault(buffer, (void *)regs->ip, MAX_INSN_SIZE))
		return -EFAULT;

	if (insn_decode(&insn, buffer, MAX_INSN_SIZE, INSN_MODE_64))
		return -EINVAL;

	mmio = insn_decode_mmio(&insn, &size);
	if (WARN_ON_ONCE(mmio == MMIO_DECODE_FAILED))
		return -EINVAL;

	if (mmio != MMIO_WRITE_IMM && mmio != MMIO_MOVS) {
		reg = insn_get_modrm_reg_ptr(&insn, regs);
		if (!reg)
			return -EINVAL;
	}

	/*
	 * Reject EPT violation #VEs that split pages.
	 *
	 * MMIO accesses are supposed to be naturally aligned and therefore
	 * never cross page boundaries. Seeing split page accesses indicates
	 * a bug or a load_unaligned_zeropad() that stepped into an MMIO page.
	 *
	 * load_unaligned_zeropad() will recover using exception fixups.
	 */
	vaddr = (unsigned long)insn_get_addr_ref(&insn, regs);
	if (vaddr / PAGE_SIZE != (vaddr + size - 1) / PAGE_SIZE)
		return -EFAULT;

	/* Handle writes first */
	switch (mmio) {
	case MMIO_WRITE:
		memcpy(&val, reg, size);
		if (!mmio_write(size, ve->gpa, val))
			return -EIO;
		return insn.length;
	case MMIO_WRITE_IMM:
		val = insn.immediate.value;
		if (!mmio_write(size, ve->gpa, val))
			return -EIO;
		return insn.length;
	case MMIO_READ:
	case MMIO_READ_ZERO_EXTEND:
	case MMIO_READ_SIGN_EXTEND:
		/* Reads are handled below */
		break;
	case MMIO_MOVS:
	case MMIO_DECODE_FAILED:
		/*
		 * MMIO was accessed with an instruction that could not be
		 * decoded or handled properly. It was likely not using io.h
		 * helpers or accessed MMIO accidentally.
		 */
		return -EINVAL;
	default:
		WARN_ONCE(1, "Unknown insn_decode_mmio() decode value?");
		return -EINVAL;
	}

	/* Handle reads */
	if (!mmio_read(size, ve->gpa, &val))
		return -EIO;

	switch (mmio) {
	case MMIO_READ:
		/* Zero-extend for 32-bit operation */
		extend_size = size == 4 ? sizeof(*reg) : 0;
		break;
	case MMIO_READ_ZERO_EXTEND:
		/* Zero extend based on operand size */
		extend_size = insn.opnd_bytes;
		break;
	case MMIO_READ_SIGN_EXTEND:
		/* Sign extend based on operand size */
		extend_size = insn.opnd_bytes;
		if (size == 1 && val & BIT(7))
			extend_val = 0xFF;
		else if (size > 1 && val & BIT(15))
			extend_val = 0xFF;
		break;
	default:
		/* All other cases has to be covered with the first switch() */
		WARN_ON_ONCE(1);
		return -EINVAL;
	}

	if (extend_size)
		memset(reg, extend_val, extend_size);
	memcpy(reg, &val, size);
	return insn.length;
}

static bool handle_in(struct pt_regs *regs, int size, int port)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_IO_INSTRUCTION),
		.r12 = size,
		.r13 = PORT_READ,
		.r14 = port,
	};
	u64 mask = GENMASK(BITS_PER_BYTE * size, 0);
	bool success;

	/*
	 * Emulate the I/O read via hypercall. More info about ABI can be found
	 * in TDX Guest-Host-Communication Interface (GHCI) section titled
	 * "TDG.VP.VMCALL<Instruction.IO>".
	 */
	success = !__tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT);

	/* Update part of the register affected by the emulated instruction */
	regs->ax &= ~mask;
	if (success)
		regs->ax |= args.r11 & mask;

	return success;
}

static bool handle_out(struct pt_regs *regs, int size, int port)
{
	u64 mask = GENMASK(BITS_PER_BYTE * size, 0);

	/*
	 * Emulate the I/O write via hypercall. More info about ABI can be found
	 * in TDX Guest-Host-Communication Interface (GHCI) section titled
	 * "TDG.VP.VMCALL<Instruction.IO>".
	 */
	return !_tdx_hypercall(hcall_func(EXIT_REASON_IO_INSTRUCTION), size,
			       PORT_WRITE, port, regs->ax & mask);
}

/*
 * Emulate I/O using hypercall.
 *
 * Assumes the IO instruction was using ax, which is enforced
 * by the standard io.h macros.
 *
 * Return True on success or False on failure.
 */
static int handle_io(struct pt_regs *regs, struct ve_info *ve)
{
	u32 exit_qual = ve->exit_qual;
	int size, port;
	bool in, ret;

	if (VE_IS_IO_STRING(exit_qual))
		return -EIO;

	in   = VE_IS_IO_IN(exit_qual);
	size = VE_GET_IO_SIZE(exit_qual);
	port = VE_GET_PORT_NUM(exit_qual);


	if (in)
		ret = handle_in(regs, size, port);
	else
		ret = handle_out(regs, size, port);
	if (!ret)
		return -EIO;

	return ve_instr_len(ve);
}

/*
 * Early #VE exception handler. Only handles a subset of port I/O.
 * Intended only for earlyprintk. If failed, return false.
 */
__init bool tdx_early_handle_ve(struct pt_regs *regs)
{
	struct ve_info ve;
	int insn_len;

	tdx_get_ve_info(&ve);

	if (ve.exit_reason != EXIT_REASON_IO_INSTRUCTION)
		return false;

	insn_len = handle_io(regs, &ve);
	if (insn_len < 0)
		return false;

	regs->ip += insn_len;
	return true;
}

void tdx_get_ve_info(struct ve_info *ve)
{
	struct tdx_module_output out;

	/*
	 * Called during #VE handling to retrieve the #VE info from the
	 * TDX module.
	 *
	 * This has to be called early in #VE handling.  A "nested" #VE which
	 * occurs before this will raise a #DF and is not recoverable.
	 *
	 * The call retrieves the #VE info from the TDX module, which also
	 * clears the "#VE valid" flag. This must be done before anything else
	 * because any #VE that occurs while the valid flag is set will lead to
	 * #DF.
	 *
	 * Note, the TDX module treats virtual NMIs as inhibited if the #VE
	 * valid flag is set. It means that NMI=>#VE will not result in a #DF.
	 */
	tdx_module_call(TDX_GET_VEINFO, 0, 0, 0, 0, &out);

	/* Transfer the output parameters */
	ve->exit_reason = out.rcx;
	ve->exit_qual   = out.rdx;
	ve->gla         = out.r8;
	ve->gpa         = out.r9;
	ve->instr_len   = lower_32_bits(out.r10);
	ve->instr_info  = upper_32_bits(out.r10);
}

/*
 * Handle the user initiated #VE.
 *
 * On success, returns the number of bytes RIP should be incremented (>=0)
 * or -errno on error.
 */
static int virt_exception_user(struct pt_regs *regs, struct ve_info *ve)
{
	switch (ve->exit_reason) {
	case EXIT_REASON_CPUID:
		return handle_cpuid(regs, ve);
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		return -EIO;
	}
}

/*
 * Handle the kernel #VE.
 *
 * On success, returns the number of bytes RIP should be incremented (>=0)
 * or -errno on error.
 */
static int virt_exception_kernel(struct pt_regs *regs, struct ve_info *ve)
{
	trace_tdx_virtualization_exception_rcuidle(regs->ip, ve->exit_reason,
						   ve->exit_qual, ve->gpa,
						   ve->instr_len,
						   ve->instr_info, regs->cx,
						   regs->ax, regs->dx);

	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		return handle_halt(ve);
	case EXIT_REASON_MSR_READ:
		return read_msr(regs, ve);
	case EXIT_REASON_MSR_WRITE:
		return write_msr(regs, ve);
	case EXIT_REASON_CPUID:
		return handle_cpuid(regs, ve);
	case EXIT_REASON_EPT_VIOLATION:
		if (!(ve->gpa & cc_mkdec(0))) {
			panic("#VE due to access to unaccepted memory. "
			      "GPA: %#llx\n", ve->gpa);
		}

		return handle_mmio(regs, ve);
	case EXIT_REASON_IO_INSTRUCTION:
		return handle_io(regs, ve);
	case EXIT_REASON_WBINVD:
		WARN_ONCE(1, "Unexpected WBINVD\n");
		return true;
	case EXIT_REASON_MONITOR_INSTRUCTION:
	case EXIT_REASON_MWAIT_INSTRUCTION:
		/*
		 * Something in the kernel used MONITOR or MWAIT despite
		 * X86_FEATURE_MWAIT being cleared for TDX guests.
		 */
		WARN_ONCE(1, "TD Guest used unsupported MWAIT/MONITOR instruction\n");
		return true;
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		return -EIO;
	}
}

bool tdx_handle_virt_exception(struct pt_regs *regs, struct ve_info *ve)
{
	int insn_len;

	if (user_mode(regs))
		insn_len = virt_exception_user(regs, ve);
	else
		insn_len = virt_exception_kernel(regs, ve);
	if (insn_len < 0)
		return false;

	/* After successful #VE handling, move the IP */
	regs->ip += insn_len;
	if (regs->flags & X86_EFLAGS_TF) {
		/*
		 * Single-stepping through an emulated instruction is
		 * two-fold: handling the #VE and raising a #DB. The
		 * former is taken care of above; this tells the #VE
		 * trap handler to do the latter. #DB is raised after
		 * the instruction has been executed; the IP also needs
		 * to be advanced in this case.
		 */
		return false;
	}

	return true;
}

static bool tdx_tlb_flush_required(bool private)
{
	/*
	 * TDX guest is responsible for flushing TLB on private->shared
	 * transition. VMM is responsible for flushing on shared->private.
	 *
	 * The VMM _can't_ flush private addresses as it can't generate PAs
	 * with the guest's HKID.  Shared memory isn't subject to integrity
	 * checking, i.e. the VMM doesn't need to flush for its own protection.
	 *
	 * There's no need to flush when converting from shared to private,
	 * as flushing is the VMM's responsibility in this case, e.g. it must
	 * flush to avoid integrity failures in the face of a buggy or
	 * malicious guest.
	 */
	return !private;
}

static bool tdx_cache_flush_required(void)
{
	/*
	 * AMD SME/SEV can avoid cache flushing if HW enforces cache coherence.
	 * TDX doesn't have such capability.
	 *
	 * Flush cache unconditionally.
	 */
	return true;
}

static bool try_accept_one(phys_addr_t *start, unsigned long len,
			  enum pg_level pg_level)
{
	unsigned long accept_size = page_level_size(pg_level);
	u64 tdcall_rcx;
	u8 page_size;

	if (!IS_ALIGNED(*start, accept_size))
		return false;

	if (len < accept_size)
		return false;

	/*
	 * Pass the page physical address to the TDX module to accept the
	 * pending, private page.
	 *
	 * Bits 2:0 of RCX encode page size: 0 - 4K, 1 - 2M, 2 - 1G.
	 */
	switch (pg_level) {
	case PG_LEVEL_4K:
		page_size = 0;
		break;
	case PG_LEVEL_2M:
		page_size = 1;
		break;
	case PG_LEVEL_1G:
		page_size = 2;
		break;
	default:
		return false;
	}

	tdcall_rcx = *start | page_size;
	if (__tdx_module_call(TDX_ACCEPT_PAGE, tdcall_rcx, 0, 0, 0, NULL))
		return false;

	*start += accept_size;
	return true;
}

static bool __tdx_enc_status_changed(phys_addr_t start, phys_addr_t end, bool enc)
{
	if (!enc) {
		/* Set the shared (decrypted) bits: */
		start |= cc_mkdec(0);
		end   |= cc_mkdec(0);
	}

	/*
	 * Notify the VMM about page mapping conversion. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface (GHCI),
	 * section "TDG.VP.VMCALL<MapGPA>"
	 */
	if (_tdx_hypercall(TDVMCALL_MAP_GPA, start, end - start, 0, 0))
		return false;

	/* private->shared conversion  requires only MapGPA call */
	if (!enc)
		return true;

	/*
	 * For shared->private conversion, accept the page using
	 * TDX_ACCEPT_PAGE TDX module call.
	 */
	while (start < end) {
		unsigned long len = end - start;

		/*
		 * Try larger accepts first. It gives chance to VMM to keep
		 * 1G/2M SEPT entries where possible and speeds up process by
		 * cutting number of hypercalls (if successful).
		 */

		if (try_accept_one(&start, len, PG_LEVEL_1G))
			continue;

		if (try_accept_one(&start, len, PG_LEVEL_2M))
			continue;

		if (!try_accept_one(&start, len, PG_LEVEL_4K))
			return false;
	}

	return true;
}
/*
 * Inform the VMM of the guest's intent for this physical page: shared with
 * the VMM or private to the guest.  The VMM is expected to change its mapping
 * of the page in response.
 */
static bool tdx_enc_status_changed(unsigned long vaddr, int numpages, bool enc)
{
	phys_addr_t start = __pa(vaddr);
	phys_addr_t end   = __pa(vaddr + numpages * PAGE_SIZE);

	return __tdx_enc_status_changed(start, end, enc);
}

void tdx_accept_memory(phys_addr_t start, phys_addr_t end)
{
	if (!__tdx_enc_status_changed(start, end, true))
		panic("Accepting memory failed\n");
}


void __init tdx_early_init(void)
{
	u64 cc_mask;
	u32 eax, sig[3];

	if (cmdline_find_option_bool(boot_command_line, "force_tdx_guest")) {
		pr_info("Force enabling TDX Guest feature\n");
	} else {
		cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2],  &sig[1]);

		if (memcmp(TDX_IDENT, sig, sizeof(sig)))
			return;
	}

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);
	setup_clear_cpu_cap(X86_FEATURE_MCE);
	setup_clear_cpu_cap(X86_FEATURE_MTRR);
	setup_clear_cpu_cap(X86_FEATURE_APERFMPERF);
	setup_clear_cpu_cap(X86_FEATURE_TME);
	setup_clear_cpu_cap(X86_FEATURE_CQM_LLC);

	cc_set_vendor(CC_VENDOR_INTEL);
	cc_mask = get_cc_mask();
	cc_set_mask(cc_mask);

	/*
	 * The only secure (mononotonous) timer inside a TD guest
	 * is the TSC. The TDX module does various checks on the TSC.
	 * There are no other reliable fall back options. Also checking
	 * against jiffies is very unreliable. So force the TSC reliable.
	 */
	setup_force_cpu_cap(X86_FEATURE_TSC_RELIABLE);

	/*
	 * All bits above GPA width are reserved and kernel treats shared bit
	 * as flag, not as part of physical address.
	 *
	 * Adjust physical mask to only cover valid GPA bits.
	 */
	physical_mask &= cc_mask - 1;

	x86_platform.guest.enc_cache_flush_required = tdx_cache_flush_required;
	x86_platform.guest.enc_tlb_flush_required   = tdx_tlb_flush_required;
	x86_platform.guest.enc_status_change_finish = tdx_enc_status_changed;

	legacy_pic = &null_legacy_pic;

	/*
	 * Disable NMI watchdog because of the risk of false positives
	 * and also can increase overhead in the TDX module.
	 * This is already done for KVM, but covers other hypervisors
	 * here.
	 */
	hardlockup_detector_disable();

	/*
	 * In TDX relying on environmental noise like interrupt
	 * timing alone is dubious, because it can be directly
	 * controlled by a untrusted hypervisor. Make sure to
	 * mix in the CPU hardware random number generator too.
	 */
	random_enable_trust_cpu();

	/*
	 * Make sure there is a panic if something goes wrong,
	 * just in case it's some kind of host attack.
	 */
	panic_on_oops = 1;

	alloc_intr_gate(TDX_GUEST_EVENT_NOTIFY_VECTOR,
			asm_sysvec_tdx_event_notify);

	if (tdx_hcall_set_notify_intr(TDX_GUEST_EVENT_NOTIFY_VECTOR))
		pr_warn("Setting event notification interrupt failed\n");

	pci_disable_early();
	pci_disable_mmconf();

	pr_info("Guest detected\n");
}
