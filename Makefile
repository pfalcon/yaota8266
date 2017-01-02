all:
	$(MAKE) -C boot8266
	$(MAKE) -C ota-server
	python merge.py -o yaota8266.bin boot8266/boot8266-0x00000.bin \
	    ota-server/ota.elf-0x00000.bin ota-server/ota.elf-0x09000.bin

clean:
	$(MAKE) -C boot8266 clean
	$(MAKE) -C ota-server clean
