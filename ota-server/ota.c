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
#include "lwip/udp.h"
#include "lwip/timers.h"
#include "ets_alt_task.h"
#include "user_interface.h"
#include "lib/axtls/crypto/crypto.h"
#define MD5_CTX MD5_CTX
#include "../boot8266/etshal.h"
#include "../config.h"

#define OTA_START MAIN_APP_OFFSET

#define CHECK(v) if (v != ERR_OK) printf(#v ": err\n")

struct pkt_seq {
    uint32_t seq;
} __attribute__((packed));

struct pkt_header {
    uint16_t op;
    uint16_t len;
    uint32_t offset;
    char data[0];
} __attribute__((packed));

static uint8_t MOD[] = MODULUS;
#define RSA_BLK_SIZE (sizeof(MOD) - 1)

static uint32_t ota_offset, ota_prev_offset;
static int dup_pkt;
static uint32_t session_start_time;
static uint32_t last_pkt_time;
static RSA_CTX *rsa_ctx = NULL;

static char buf[4096];
static int buf_sz;

#define AES_BLK_SIZE 16
uint8_t AES_IV[AES_BLK_SIZE] = {0};


static void buf_init(void) {
    buf_sz = 0;
    memset(buf, 0xff, sizeof(buf));
}

#define MP_FASTCODE(n) __attribute__((section(".iram0.text." #n))) n

void MP_FASTCODE(write_buf)(void) {
    if (buf_sz > 0) {
#if 0
        printf("Would write %d bytes of buf\n", buf_sz);
#else
        uint32_t off = OTA_START + ota_offset;
        if (off & (4096 - 1)) {
            off &= ~(4096 - 1);
        } else {
            off -= 4096;
        }
        printf("Writing %d bytes of buf to %x\n", buf_sz, off);
        SPIEraseSector(off / 4096);
        SPIWrite(off, buf, sizeof(buf));
#endif
    }
    buf_init();
}

static void session_init(void) {
    dup_pkt = 0;
    ota_offset = 0;
    ota_prev_offset = -1;
    session_start_time = system_get_time();
}

static void ota_udp_incoming(void *arg, struct udp_pcb *upcb, struct pbuf *p, ip_addr_t *addr, u16_t port) {

    printf("UDP incoming from: %x:%d, data=%p\n", (unsigned)addr->addr, port, p->payload);
    uint32_t start_time = system_get_time();

    if (p->len < sizeof(struct pkt_header)) {
        printf("Packet too short\n");
        goto done;
    }

    struct pkt_seq *pkt = p->payload;
    printf("Pkt id: %x\n", pkt->seq);

    uint8_t sig_payload[RSA_BLK_SIZE];
    uint8_t *sig = (uint8_t*)p->payload + p->len - RSA_BLK_SIZE;
    int sig_sz = RSA_decrypt(rsa_ctx, sig, sig_payload, sizeof(sig_payload), 0);
    if (sig_sz != SHA1_SIZE + AES_BLK_SIZE) {
        printf("Invalid digest size in signature\n");
        goto done;
    }

    struct pkt_header *hdr = (struct pkt_header*)((char*)p->payload + 4);

    SHA1_CTX sha_ctx;
    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, (uint8_t*)hdr, p->len - RSA_BLK_SIZE - 4);
    uint8_t digest[SHA1_SIZE];
    SHA1_Final(digest, &sha_ctx);

    if (memcmp(digest, sig_payload + AES_BLK_SIZE, sizeof(digest)) != 0) {
        printf("Invalid SHA1\n");
        goto done;
    }

#if 0
    AES_CTX aes_ctx;
    AES_set_key(&aes_ctx, sig_payload, AES_IV, AES_MODE_128);
    AES_convert_key(&aes_ctx);
    AES_cbc_decrypt(&aes_ctx, (uint8_t*)hdr, (uint8_t*)hdr, p->len - RSA_BLK_SIZE - 4);
#endif

    printf("offset: %d len: %d\n", hdr->offset, hdr->len);

    if (hdr->len == 0) {
        write_buf();
        printf("OTA finished, rexmits: %d\n", dup_pkt);
        pbuf_free(p);
        session_init();

        //udp_remove(upcb);
        printf("Rebooting\n");
        system_restart();

        return;
    }

    if (hdr->offset == ota_prev_offset) {
        // Client apparently didn't receive our confirmation
        // and went to resend the packet we already processed -
        // resend the confirmation.
        dup_pkt++;
        goto confirm;
    }

    if (hdr->offset != ota_offset) {
        printf("Unexpected offset\n");
        goto done;
    }
    if (buf_sz + hdr->len > sizeof(buf)) {
        printf("Buffer overflow - wrong chunk size\n");
        goto done;
    }
    memcpy(buf + buf_sz, hdr->data, hdr->len);
    ota_prev_offset = ota_offset;
    ota_offset += hdr->len;
    buf_sz += hdr->len;

    printf("Proc1 time: %d\n", system_get_time() - start_time);

    if (buf_sz == sizeof(buf)) {
        write_buf();
    }

confirm: {
      struct pbuf *resp = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct pkt_seq) + AES_BLK_SIZE, PBUF_RAM);
      *(uint32_t*)resp->payload = pkt->seq;
      uint8_t *encblk = (uint8_t*)resp->payload + 4;
      memcpy(encblk, hdr, sizeof(struct pkt_header));
#if 0
      AES_set_key(&aes_ctx, sig_payload, AES_IV, AES_MODE_128);
      AES_cbc_encrypt(&aes_ctx, encblk, encblk, AES_BLK_SIZE);
#endif

      CHECK(udp_sendto(upcb, resp, addr, port));
      pbuf_free(resp);
    }

    last_pkt_time = system_get_time();

done:
    printf("Full time: %d\n", system_get_time() - start_time);
    pbuf_free(p);
}

void timer_handler(void *arg) {
    //printf("tick\n");

    if (ota_prev_offset != -1 && system_get_time() - last_pkt_time > PKT_WAIT_MS * 1000) {
        printf("Next pkt wait timeout, restarting recv\n");
        session_init();
    }

    if (ota_prev_offset == -1 && system_get_time() - session_start_time > IDLE_REBOOT_MS * 1000) {
        printf("OTA start timeout, rebooting\n");
        system_restart();
    }

    sys_timeout(1000, timer_handler, NULL);
}

void ota_start(void) {
    session_init();
    buf_init();

    RSA_pub_key_new(&rsa_ctx, MOD, sizeof(MOD) - 1, (uint8_t*)"\x03", 1);
    printf("rsa_ctx = %p\n", rsa_ctx);

    struct udp_pcb *sock = udp_new();
    CHECK(udp_bind(sock, IP_ADDR_ANY, 8266));
    udp_recv(sock, ota_udp_incoming, NULL);

    sys_timeout(1000, timer_handler, NULL);

    while (1) {
        ets_loop_iter();
    }
}
