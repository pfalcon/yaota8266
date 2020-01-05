default: help


help:  ## This help page
	@echo 'make targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-17s %s\n", $$1, $$2}'

print-rsa-modulus: ## Print the RSA modulus line for copy&paste into config.h
	python3 ota_client/print_rsa_modulus.py

rsa-keys:  ## Generate RSA keys and print the RSA modulus line for copy&paste into config.h
	./ota_client/gen_keys.sh
	$(MAKE) print-rsa-modulus

build:  ## Build boot8266 and ota-server and combine it to: "yaota8266.bin"
	$(MAKE) -C boot8266
	$(MAKE) -C ota_server
	python merge.py -o yaota8266.bin boot8266/boot8266-0x00000.bin \
	    ota_server/ota.elf-0x00000.bin ota_server/ota.elf-0x09000.bin


clean:  ## clean builded files
	$(MAKE) -C boot8266 clean
	$(MAKE) -C ota_server clean
