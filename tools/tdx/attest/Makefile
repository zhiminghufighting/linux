# SPDX-License-Identifier: GPL-2.0
# Makefile for TDX atteste test sample
#

######## Tdx_Attest_Test Sample Settings ########
Protobuf_CFLAGS = `pkg-config --cflags libprotobuf-c`
Protobuf_LFLAGS = `pkg-config --libs libprotobuf-c`

Tdx_Attest_C_Files := tdx-attest-test.c

Tdx_Attest_Include_Paths := -I./

Tdx_Attest_C_Flags := -g -fPIC -Wno-attributes $(Tdx_Attest_Include_Paths)

Tdx_Attest_C_Flags := $(Tdx_Attest_C_Flags)

LDUFLAGS:= -Wl,--gc-sections

Tdx_Attest_C_Objects := $(Tdx_Attest_C_Files:.c=.o)

Tdx_Attest_Name := tdx-attest-test

.PHONY: all attest-test

######## Tdx_Attest_Test Sample ########
$(Tdx_Attest_Name): qgs.message.pb-c.o $(Tdx_Attest_C_Objects)
	$(CC) qgs.message.pb-c.o $(Tdx_Attest_C_Objects) $(Protobuf_LFLAGS) $(LDUFLAGS) -o $@
	@echo "LINK =>  $@"

$(Tdx_Attest_C_Objects): %.o: qgs.message.pb-c.o %.c
	$(CC) $(Tdx_Attest_C_Flags) -c $(Tdx_Attest_C_Files) -o $@
	@echo "CXX  <=  $<"

qgs.message.pb-c.o: qgs/qgs.message.proto
	protoc --c_out=. --proto_path=. qgs/qgs.message.proto
	$(CC) -g -c qgs/qgs.message.pb-c.c -I. $(Protobuf_CFLAGS) -fPIC

.PHONY: clean

clean:
	@rm -rf $(Tdx_Attest_Name) $(Tdx_Attest_C_Objects) qgs.message.pb-c.o qgs/qgs.message.pb-c.c qgs/qgs.message.pb-c.h
