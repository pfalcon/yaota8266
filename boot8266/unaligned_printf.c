#include <stdarg.h>
#include <stdint.h>

extern char _bss_end;
extern void ets_write_char();
extern int ets_vprintf(void (*)(), const char *, va_list);

/* Print unaligned string residing in aligned memory (iRAM, iROM) using
   standard ets_printf(). Do so by copying string to dRAM first. Note
   that this overwrites dRAM beyond BSS end, and so not suitable for
   use in full-fledged apps, but rather for low-level stuff like
   bootloaders. */
int _printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    uint32_t addr = (uint32_t)fmt;

    uint32_t *p = (uint32_t*)(addr&~3), *to = (uint32_t*)&_bss_end;
    while (1) {
        uint32_t v = *p++;
        *to++ = v;
        if ((uint32_t)p > (addr&~3)) {
            if (!(v & 0xff) || !(v & 0xff00) || !(v & 0xff0000) || !(v & 0xff000000)) break;
        }
    }
    return ets_vprintf(ets_write_char, &_bss_end + (addr&3), args);
}
