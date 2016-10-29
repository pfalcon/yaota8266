/*
 * This file is part of the yaota8266 project.
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Paul Sokolovsky
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <string.h>

#include "ets_sys.h"
#include "gpio.h"

#define MAIN_APP_OFFSET 0x3c000

uint32_t SPIRead(uint32_t offset, void *buf, uint32_t len);
uint32_t SPIWrite(uint32_t offset, const void *buf, uint32_t len);
void _printf(const char *, ...);

#define CPU_TICKS_PER_MS 80000

__attribute__((always_inline)) static inline uint32_t ticks_cpu(void) {
  uint32_t ccount;
  __asm__ __volatile__("rsr %0,ccount":"=a" (ccount));
  return ccount;
}

struct flash_header {
    uint8_t sig;
    uint8_t num;
    uint8_t par1;
    uint8_t par2;
    uint32_t start;
};

struct sect_header {
    void *addr;
    uint32_t size;
};

// Return true if OTA should start
bool check_buttons(void)
{
    gpio_init();

    PIN_FUNC_SELECT(PERIPHS_IO_MUX_GPIO0_U, FUNC_GPIO0);
    PIN_PULLUP_DIS(PERIPHS_IO_MUX_GPIO0_U);

    uint32_t gpio_ini = gpio_input_get();
    _printf("Initial GPIO state: %x, OE: %x\n", gpio_ini, *(uint32_t*)0x60000314);
    bool ota = false;
    int ms_delay = 3000;
    uint32_t ticks = ticks_cpu();
    while (ms_delay) {
        uint32_t gpio_last = gpio_input_get();
        if (gpio_last != gpio_ini) {
            _printf("GPIO changed: %x\n", gpio_last);
            ota = true;
            break;
        }
        if (ticks_cpu() - ticks > CPU_TICKS_PER_MS) {
            ms_delay--;
            ticks += CPU_TICKS_PER_MS;
        }
        //system_soft_wdt_feed();
    }

    return ota;
}

void start()
{
    uint32_t offset;
    _printf("boot8266\n");
    memset((void*)0x3ffe8000, 0, 0x3fffc000 - 0x3ffe8000);

    bool ota = check_buttons();

    if (ota) {
        _printf("Running OTA\n");
        offset = 0x1000;
    } else {
        _printf("Running app\n");
        offset = MAIN_APP_OFFSET;
    }

    union {
        struct flash_header flash;
        struct sect_header sect;
    } hdr;

    SPIRead(offset, &hdr.flash, sizeof(hdr.flash));
    offset += sizeof(hdr.flash);

    register uint32_t start = hdr.flash.start;
    int num = hdr.flash.num;

    register uint32_t iram_offset = 0;
    register void *iram_addr = NULL;
    register uint32_t iram_size = 0;

    // Any _printf() beyond this point may (will) corrupt memory
    while (num--) {
        SPIRead(offset, &hdr.sect, sizeof(hdr.sect));
        offset += sizeof(hdr.sect);
        //_printf("off: %x addr: %x size: %x\n", offset, hdr.sect.addr, hdr.sect.size);
        if (hdr.sect.addr >= (void*)0x40100000 && hdr.sect.addr < (void*)0x40108000) {
            //_printf("skip iram\n");
            iram_offset = offset;
            iram_addr = hdr.sect.addr;
            iram_size = hdr.sect.size;
        } else {
            //_printf("load\n");
            SPIRead(offset, hdr.sect.addr, hdr.sect.size);
        }
        offset += hdr.sect.size;
    }

    //_printf("iram: %x %p %x s: %x\n", iram_offset, iram_addr, iram_size, start);

    asm volatile ("mov a5, %0" : : "r" (SPIRead));
    asm volatile ("mov a0, %0" : : "r" (start));
    asm volatile ("mov a3, %0" : : "r" (iram_addr));
    asm volatile ("mov a4, %0" : : "r" (iram_size));
    asm volatile ("mov a1, %0" : : "r" (0x40000000));
    asm volatile ("mov a2, %0" : : "r" (iram_offset));
    asm volatile ("jx a5\n");
}
