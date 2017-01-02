CC = xtensa-lx106-elf-gcc
# -O0 is mandatory, anything else will break inline asm
CFLAGS = -O0 -I. -mlongcalls -ffunction-sections -fdata-sections
LDLIBS = -nostdlib -lgcc
LDFLAGS = -T./boot8266.ld -e start -Wl,-Map=$@.map -Wl,--cref

boot8266-0x00000.bin: boot8266
	esptool.py elf2image $^

boot8266: boot8266.o unaligned_printf.o

boot8266.o: boot8266.c
unaligned_printf.o: unaligned_printf.c

# Force re-link if .ld is updated
boot8266.o: boot8266.ld

flash: boot8266-0x00000.bin
	esptool.py write_flash 0 $^

clean:
	rm -f boot8266 *.o boot8266-0x*
