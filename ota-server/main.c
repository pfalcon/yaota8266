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
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "user_interface.h"
#include "mem.h"
#include "../boot8266/etshal.h"
#include "../config.h"

void ota_start(void);

void init_done(void) {
#if BAUD_RATE
    uart_div_modify(0, UART_CLK_FREQ / BAUD_RATE);
#endif
    printf("\nStarting OTA server\n");
    ota_start();
}

void user_init(void) {
    system_init_done_cb(init_done);
}

//void __assert(const char *file, int line, const char *func, const char *expr) {
void __assert(const char *file, int line, const char *expr) {
    printf("Assertion '%s' failed, at file %s:%d\n", expr, file, line);
    for (;;) {
    }
}

void abort_(void) {
    printf("Abort\n");
    for (;;);
}

void *malloc(int sz) {
    return os_malloc(sz);
}

void *realloc(void *p, int sz) {
    return os_realloc(p, sz);
}

void *calloc(int n, int sz) {
    return os_zalloc(n * sz);
}

void free(void *p) {
    return os_free(p);
}

#define PLATFORM_HTONL(_n) ((uint32_t)( (((_n) & 0xff) << 24) | (((_n) & 0xff00) << 8) | (((_n) >> 8)  & 0xff00) | (((_n) >> 24) & 0xff) ))
#undef htonl
#undef ntohl
uint32_t ntohl(uint32_t netlong) {
    return PLATFORM_HTONL(netlong);
}
uint32_t htonl(uint32_t netlong) {
    return PLATFORM_HTONL(netlong);
}

extern void ets_write_char();
extern int ets_printf(const char *, ...);
extern int ets_vprintf(void (*)(), const char *, va_list);

int puts(const char *s) {
    ets_printf(s);
    ets_printf("\n");
}

int printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    return ets_vprintf(ets_write_char, fmt, args);
}

int DEBUG_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    return ets_vprintf(ets_write_char, fmt, args);
}
