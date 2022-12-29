/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_MISC_TDX_H
#define _UAPI_MISC_TDX_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* Input report data length for TDX_CMD_GET_TDREPORT IOCTL request */
#define TDX_REPORT_DATA_LEN		64

/* Output TD report data length after TDX_CMD_GET_TDREPORT IOCTL execution */
#define TDX_TDREPORT_LEN		1024

/* Input data length for EXTEND_RTMR (not including index) */
#define TDX_EXTEND_LEN			48

/*
 * TDX_CMD_GET_TDREPORT IOCTL is used to get TDREPORT data from the TDX
 * Module. Users should pass report data of size TDX_REPORT_DATA_LEN bytes
 * via user input buffer of size TDX_TDREPORT_LEN. Once IOCTL is successful
 * TDREPORT data is copied to the user buffer.
 */
#define TDX_CMD_GET_TDREPORT		_IOWR('T', 0x01, __u64)

/*
 * TDX_CMD_GEN_QUOTE IOCTL is used to request TD QUOTE from the VMM. User
 * should pass TD report data of size TDX_TDREPORT_LEN bytes via user input
 * buffer of quote size. Once IOCTL is successful quote data is copied back to
 * the user buffer.
 */
#define TDX_CMD_GEN_QUOTE		_IOR('T', 0x02, __u64)

/*
 * TDX_CMD_GET_QUOTE_SIZE IOCTL is used to get the TD Quote size info in bytes.
 * This will be used for determining the input buffer allocation size when
 * using TDX_CMD_GEN_QUOTE IOCTL.
 */
#define TDX_CMD_GET_QUOTE_SIZE		_IOR('T', 0x03, __u64)

/*
 * Extend a TDX measurement register (RTMR) by input data.
 * The first u64 of the buffer is the RTMR index, then the remaining
 * is a hash value of the length returned by TDX_CMD_GET_EXTEND_SIZE
 */
#define TDX_CMD_EXTEND_RTMR		_IOR('T', 0x04, __u64)

/* Report input buffer size for TDX_CMD_EXTEND_RTMR */
#define TDX_CMD_GET_EXTEND_SIZE		_IOR('T', 0x05, __u64)

#endif /* _UAPI_MISC_TDX_H */
