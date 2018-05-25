CC = xtensa-lx106-elf-gcc
LD = xtensa-lx106-elf-ld
AR = xtensa-lx106-elf-ar
ESP_SDK = $(shell $(CC) -print-sysroot)/usr
CFLAGS = -std=gnu99 -Os -I. -mtext-section-literals -mlongcalls -mforce-l32 -ffunction-sections -fdata-sections -DLWIP_OPEN_SRC -D__ets__
LDLIBS = -L$(ESP_SDK)/lib -L. -laxtls -lmain -lnet80211 -lwpa -llwip_open -lpp -lphy -lnet80211 -lgcc
LDFLAGS = -nostdlib -T./ota.ld -gc-sections -Map=$@.map --cref

ota-0x00000.bin: ota.elf
	esptool.py elf2image $^

ota.elf: ota.o main.o ets_alt_task.o | libaxtls.a
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

libaxtls.a:
	cd lib/axtls; cp config/upyconfig config/.config
	cd lib/axtls; make oldconfig -B
	cd lib/axtls; make clean
	cd lib/axtls; make all CC="$(CC)" LD="$(LD)" AR="$(AR)" CFLAGS_EXTRA="$(CFLAGS) -Dabort=abort_ -DRT_MAX_PLAIN_LENGTH=1024 -DRT_EXTRA=3072"
	cp lib/axtls/_stage/libaxtls.a $@

flash: ota-0x00000.bin
	esptool.py --baud 1500000 write_flash 0 *-0x00000.bin 0x8000 *-0x08000.bin

clean:
	rm -f *.o *.a *.elf* *-0x*.bin
