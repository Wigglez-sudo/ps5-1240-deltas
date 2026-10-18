.PHONY: all clean

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN := bin/ps5-linux-loader.elf
PROBE_SRC := source/efimeta_probe.c source/oracle_probe.c source/physmem_probe.c \
             source/propro_probe.c source/propro_probe2.c source/viola_probe.c \
             source/wakepa_probe.c source/wakepa_probe_1160.c source/wakepa_probe_1360.c
SRC := $(filter-out $(PROBE_SRC),$(wildcard source/*.c))
OBJS := $(SRC:.c=.o)

CFLAGS  := -std=c23 -Wall -Iinclude -Ishellcode_hv -Ishellcode_kernel $(EXTRA_CFLAGS)
LDFLAGS :=

SC_HV_H := shellcode_hv/shellcode_hv.h
SC_K_H  := shellcode_kernel/shellcode_kernel.h
SC_AP_H := shellcode_ap/shellcode_ap.h

SC_HV_SRC   := $(wildcard shellcode_hv/*.c shellcode_hv/*.S shellcode_hv/*.h shellcode_hv/*.ld)
SC_K_SRC    := $(wildcard shellcode_kernel/*.c shellcode_kernel/*.S shellcode_kernel/*.h shellcode_kernel/*.ld)
SC_AP_SRC   := $(wildcard shellcode_ap/*.c shellcode_ap/*.S shellcode_ap/*.h shellcode_ap/*.ld)

all: $(SC_HV_H) $(SC_K_H) $(SC_AP_H) $(BIN)

$(SC_HV_H): $(SC_HV_SRC)
	$(MAKE) -C shellcode_hv

$(SC_K_H): $(SC_K_SRC)
	$(MAKE) -C shellcode_kernel

$(SC_AP_H):
	$(MAKE) -C shellcode_ap

$(OBJS): %.o: %.c $(wildcard include/*.h) $(SC_HV_H) $(SC_K_H) $(SC_AP_H)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

clean:
	rm -f $(BIN) $(OBJS)
	$(MAKE) -C shellcode_hv clean
	$(MAKE) -C shellcode_kernel clean
	$(MAKE) -C shellcode_ap clean
