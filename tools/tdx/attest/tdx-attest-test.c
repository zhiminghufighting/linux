// SPDX-License-Identifier: GPL-2.0-only
/*
 * tdx-attest-test.c - utility to test TDX attestation feature.
 *
 * Copyright (C) 2020 - 2021 Intel Corporation. All rights reserved.
 *
 * Author: Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>
 *
 */

#include <linux/types.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <getopt.h>
#include <stdint.h>
#include <sys/mman.h>
#include <time.h>

#include "../../../include/uapi/misc/tdx.h"

#include "qgs/qgs.message.pb-c.h"

#define devname         "/dev/tdx-attest"

#define HEX_DUMP_SIZE   16
#define MAX_ROW_SIZE    70

#define ATTESTATION_TEST_BIN_VERSION "0.1"

struct tdx_attest_args {
	bool is_dump_data;
	bool is_get_tdreport;
	bool is_get_quote_size;
	bool is_gen_quote;
	bool debug_mode;
	char *out_file;
};

#pragma pack(push, 1)
/* It's a 4page-bytes-long structure */
struct get_quote_blob_t {
	uint64_t version;
	uint64_t status;
	uint32_t in_len;
	uint32_t out_len;
	uint8_t trans_len[4];
	uint8_t p_buf[4 * 4 * 1024 - 28];
};

struct get_quote_ioctl_arg_t {
    void *p_blob;
    size_t len;
};
#pragma pack(pop)

struct tdx_report_t {
	uint8_t d[TDX_TDREPORT_LEN];
};

static const unsigned int HEADER_SIZE = 4;

static void print_hex_dump(const char *title, const char *prefix_str,
				const void *buf, int len)
{
	const __u8 *ptr = buf;
	int i, rowsize = HEX_DUMP_SIZE;

	if (!len || !buf)
		return;

	printf("\t\t%s", title);

	for (i = 0; i < len; i++) {
		if (!(i % rowsize))
			printf("\n%s%.8x:", prefix_str, i);
		printf(" %.2x", ptr[i]);
	}

	printf("\n");
}

static void gen_report_data(__u8 *report_data, bool dump_data)
{
	int i;

	srand(time(NULL));

	for (i = 0; i < TDX_REPORT_DATA_LEN; i++)
		report_data[i] = rand();

	if (dump_data)
		print_hex_dump("\n\t\tTDX report data\n", " ",
				report_data, TDX_REPORT_DATA_LEN);
}

static int get_tdreport(int devfd, bool dump_data, __u8 *report_data)
{
	__u8 tdrdata[TDX_TDREPORT_LEN] = {0};
	int ret;

	if (!report_data)
		report_data = tdrdata;

	gen_report_data(report_data, dump_data);

	ret = ioctl(devfd, TDX_CMD_GET_TDREPORT, report_data);
	if (ret) {
		printf("TDX_CMD_GET_TDREPORT ioctl() %d failed.\n", ret);
		return -EIO;
	}

	if (dump_data)
		print_hex_dump("\n\t\tTDX tdreport data\n", " ", report_data,
				TDX_TDREPORT_LEN);

	return 0;
}

static __u64 get_quote_size(int devfd)
{
	int ret;
	__u64 quote_size;

	ret = ioctl(devfd, TDX_CMD_GET_QUOTE_SIZE, &quote_size);
	if (ret) {
		printf("TDX_CMD_GET_QUOTE_SIZE ioctl() %d failed.\n", ret);
		return -EIO;
	}

	printf("Quote size: %lld\n", quote_size);

	return quote_size;
}

static int gen_quote(int devfd, bool dump_data)
{
	__u8 *quote_data;
	__u64 quote_size;
	int ret;
	struct tdx_report_t tdx_report;

	ret = get_tdreport(devfd, dump_data, (__u8 *)&tdx_report);
	if (ret) {
		printf("TDX_CMD_GET_TDREPORT ioctl() %d failed.\n", ret);
		goto done;
	}

	struct get_quote_blob_t *p_get_quote_blob = NULL;

	quote_size = get_quote_size(devfd);
	quote_data = malloc(sizeof(char) * quote_size);
	if (!quote_data) {
		printf("%s quote data alloc failed.\n", devname);
		return -ENOMEM;
	}

	p_get_quote_blob = (struct get_quote_blob_t *)malloc(sizeof(struct get_quote_blob_t));
	if (!p_get_quote_blob) {
		printf("%s quote blob data alloc failed.\n", devname);
		free(quote_data);
		return -ENOMEM;
	}

	Qgs__Message__Request request = QGS__MESSAGE__REQUEST__INIT;

	request.type = QGS__MESSAGE__REQUEST__MSG_GET_QUOTE_REQUEST;
	Qgs__Message__Request__GetQuoteRequest get_quote_request =
		QGS__MESSAGE__REQUEST__GET_QUOTE_REQUEST__INIT;
	get_quote_request.report.len = sizeof(tdx_report.d);
	get_quote_request.report.data = tdx_report.d;
	request.msg_case = QGS__MESSAGE__REQUEST__MSG_GET_QUOTE_REQUEST;
	request.getquoterequest = &get_quote_request;

	uint32_t msg_size = (uint32_t)qgs__message__request__get_packed_size(&request);

	p_get_quote_blob->version = 1;
	p_get_quote_blob->status = 0;
	p_get_quote_blob->in_len = HEADER_SIZE + msg_size;
	p_get_quote_blob->out_len = (uint32_t)(sizeof(*p_get_quote_blob) - 24);
	p_get_quote_blob->trans_len[0] = (uint8_t)((msg_size >> 24) & 0xFF);
	p_get_quote_blob->trans_len[1] = (uint8_t)((msg_size >> 16) & 0xFF);
	p_get_quote_blob->trans_len[2] = (uint8_t)((msg_size >> 8) & 0xFF);
	p_get_quote_blob->trans_len[3] = (uint8_t)(msg_size & 0xFF);

	/* Serialization to match qgs protobuf format */
	qgs__message__request__pack(&request, p_get_quote_blob->p_buf);

	struct get_quote_ioctl_arg_t arg;
	arg.p_blob = p_get_quote_blob;
	arg.len = sizeof(*p_get_quote_blob);

	ret = ioctl(devfd, TDX_CMD_GEN_QUOTE, &arg);
	if (ret < 0) {
		printf("TDX_CMD_GEN_QUOTE ioctl() %d failed.\n", ret);
		goto done;
	}

	if (p_get_quote_blob->status || p_get_quote_blob->out_len <= HEADER_SIZE) {
		printf("failed with status is %lx, out_len is %x.\n", p_get_quote_blob->status,
				p_get_quote_blob->out_len);
		goto done;
	}

	msg_size = p_get_quote_blob->out_len - HEADER_SIZE;

	/* Unserialization target data */
	Qgs__Message__Response *resp = qgs__message__response__unpack(
		NULL, msg_size, p_get_quote_blob->p_buf);
	if (!resp) {
		printf("failed with response is NULL.\n");
		goto done;
	}

	if (resp->type == QGS__MESSAGE__RESPONSE__MSG_GET_QUOTE_RESPONSE) {
		if (resp->getquoteresponse->error_code != 0) {
			printf("failed with response error code is %x.\n",
					resp->getquoteresponse->error_code);
			goto done;
		}

		quote_size = (uint32_t)resp->getquoteresponse->quote.len;
		memcpy(quote_data, resp->getquoteresponse->quote.data, quote_size);
	} else {
		printf("failed with response type is not MSG_GET_QUOTE_RESPONSE.\n");
		goto done;
	}

	print_hex_dump("\n\t\tTDX Quote data\n", " ", quote_data,
			quote_size);

done:
	free(quote_data);
	free(p_get_quote_blob);

	return ret;
}

static void usage(void)
{
	puts("\nUsage:\n");
	puts("tdx_attest[options]\n");
	puts("Attestation device test utility.");

	puts("\nOptions:\n");
	puts(" -d, --dump                Dump tdreport/tdquote data");
	puts(" -r, --get-tdreport        Get TDREPORT data");
	puts(" -g, --gen-quote           Generate TDQUOTE");
	puts(" -s, --get-quote-size      Get TDQUOTE size");
}

int main(int argc, char **argv)
{
	int ret, devfd;
	struct tdx_attest_args args = {0};
	static const struct option longopts[] = {
		{ "dump",           no_argument,       NULL, 'd' },
		{ "get-tdreport",   required_argument, NULL, 'r' },
		{ "gen-quote",      required_argument, NULL, 'g' },
		{ "gen-quote-size", required_argument, NULL, 's' },
		{ "version",        no_argument,       NULL, 'V' },
		{ NULL,             0, NULL, 0 }
	};

	while ((ret = getopt_long(argc, argv, "hdrgsV", longopts,
					NULL)) != -1) {
		switch (ret) {
		case 'd':
			args.is_dump_data = true;
			break;
		case 'r':
			args.is_get_tdreport = true;
			break;
		case 'g':
			args.is_gen_quote = true;
			break;
		case 's':
			args.is_get_quote_size = true;
			break;
		case 'h':
			usage();
			return 0;
		case 'V':
			printf("Version: %s\n", ATTESTATION_TEST_BIN_VERSION);
			return 0;
		default:
			printf("Invalid options\n");
			usage();
			return -EINVAL;
		}
	}

	devfd = open(devname, O_RDWR | O_SYNC);
	if (devfd < 0) {
		printf("%s open() failed\n", devname);
		return -ENODEV;
	}

	if (args.is_get_quote_size)
		get_quote_size(devfd);

	if (args.is_get_tdreport)
		get_tdreport(devfd, args.is_dump_data, NULL);

	if (args.is_gen_quote)
		gen_quote(devfd, args.is_dump_data);

	close(devfd);

	return 0;
}
