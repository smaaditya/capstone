/*
 * Host sender: reads Receiver public key, encapsulates via Kyber ref API,
 * derives AES-256 key from shared secret, encrypts an image using OpenSSL,
 * and writes a package file containing: [ct_len][iv_len][enc_len][ct||iv||enc]
 *
 * Build: make (in this directory). Requires OpenSSL dev (-lcrypto).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/rand.h>

#include "../kyber-main/ref/api.h"
#include "../kyber-main/ref/kem.h"
#include "../kyber-main/ref/fips202.h"
#include "../../RISC-V-main/RISC-V-main/test/aes/aes.h"
#include "../../RISC-V-main/RISC-V-main/lib/uart.h"

// Use CRYPTO_* constants provided by the Kyber ref headers (no redefinition)
/* Keep the ref implementation's standard `crypto_kem_*` function names so
    they link against the definitions in the ref sources (kem.c). */

static void handle_errors(const char *msg) {
    fprintf(stderr, "ERROR: %s\n", msg);
    exit(1);
}

static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    fprintf(stderr, "%s:", label);
    for (size_t i = 0; i < len; ++i) fprintf(stderr, " %02x", buf[i]);
    fprintf(stderr, "\n");
}

static unsigned char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}



int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <pk.bin|uart> <image_in> <package_out|uart>\n", argv[0]);
        return 1;
    }
    const char *pk_path = argv[1];
    const char *img_path = argv[2];
    const char *out_path = NULL;
    int use_uart = 0;
    uint32_t uart_base = 0;
    if (argc >= 4) out_path = argv[3];
    if (strcmp(pk_path, "uart") == 0) {
        if (argc < 4) { fprintf(stderr, "uart mode: host_sender uart <uart_base_hex> <image_in>\n"); return 1; }
        use_uart = 1;
        uart_base = (uint32_t)strtoul(img_path, NULL, 0);
        img_path = out_path; /* shift args: image path in argv[3] */
        out_path = NULL;
    }


    size_t pk_len;
    unsigned char *pk = NULL;
    if (!use_uart) {
        pk = read_file(pk_path, &pk_len);
        if (!pk) handle_errors("failed to read pk file");
    } else {
        /* receive pk over UART */
        uart uart_dev;
        uart_init(&uart_dev, uart_base);
        unsigned char pk_hdr[4];
        if (uart_receive(&uart_dev, pk_hdr, 4) != 4) handle_errors("failed to read pk length via uart");
        pk_len = *((uint32_t*)pk_hdr);
        pk = malloc(pk_len);
        if (!pk) handle_errors("malloc failed");
        if (uart_receive(&uart_dev, pk, pk_len) != pk_len) handle_errors("failed to read pk via uart");
        printf("Received pk (%zu bytes) over UART\n", pk_len);
    }

    size_t img_len;
    unsigned char *img = read_file(img_path, &img_len);
    if (!img) {
        fprintf(stderr, "ERROR: could not open image '%s'\n", img_path);
        exit(1);
    }
    fprintf(stderr, "input image %s length=%zu bytes\n", img_path, img_len);
    if (img_len == 0) handle_errors("image file is empty");

    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char ss[CRYPTO_BYTES];

    if (crypto_kem_enc(ct, ss, pk) != 0) handle_errors("crypto_kem_enc failed");
    print_hex("ss-host", ss, CRYPTO_BYTES);

    /* Derive AES-256 key using SHA3-256 over the shared secret (Kyber uses SHA3 family).
       This follows the KDF usage to obtain a 32-byte symmetric key. */
    /* Derive AES key length from AES_KEYLEN in repo AES; use SHA3-256 then truncate */
    unsigned char full_hash[32];
    sha3_256(full_hash, ss, CRYPTO_BYTES);
    unsigned char aes_key[AES_KEYLEN];
    memcpy(aes_key, full_hash, AES_KEYLEN);

    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) handle_errors("RAND_bytes failed");

    /* PKCS7 padding to 16-byte blocks */
    size_t pad_len = AES_BLOCKLEN - (img_len % AES_BLOCKLEN);
    size_t padded_len = img_len + pad_len;
    unsigned char *padded = malloc(padded_len);
    if (!padded) handle_errors("malloc failed");
    memcpy(padded, img, img_len);
    for (size_t i = 0; i < pad_len; ++i) padded[img_len + i] = (unsigned char)pad_len;

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aes_key, iv);
    AES_CBC_encrypt_buffer(&ctx, padded, padded_len);
    unsigned char *enc = padded;
    size_t enc_len = padded_len;

    /* Compute authentication tag using SHA3-256 over (ss || iv || enc) for integrity. */
    unsigned char *tag = malloc(32);
    unsigned char *tag_input = malloc(CRYPTO_BYTES + sizeof(iv) + enc_len);
    if (!tag || !tag_input) handle_errors("malloc failed");
    memcpy(tag_input, ss, CRYPTO_BYTES);
    memcpy(tag_input + CRYPTO_BYTES, iv, sizeof(iv));
    memcpy(tag_input + CRYPTO_BYTES + sizeof(iv), enc, enc_len);
    sha3_256(tag, tag_input, (unsigned long long)(CRYPTO_BYTES + sizeof(iv) + enc_len));
    print_hex("tag-host", tag, 32);
    free(tag_input);

    uint32_t ct_len_u = CRYPTO_CIPHERTEXTBYTES;
    uint32_t iv_len_u = sizeof(iv);
    uint32_t enc_len_u = (uint32_t)enc_len;
    uint32_t tag_len_u = 32;

    if (!use_uart) {
        FILE *out = fopen(out_path, "wb");
        if (!out) handle_errors("failed to open output file");
        fwrite(&ct_len_u, sizeof(ct_len_u), 1, out);
        fwrite(&iv_len_u, sizeof(iv_len_u), 1, out);
        fwrite(&enc_len_u, sizeof(enc_len_u), 1, out);
        fwrite(&tag_len_u, sizeof(tag_len_u), 1, out);
        fwrite(ct, 1, CRYPTO_CIPHERTEXTBYTES, out);
        fwrite(iv, 1, sizeof(iv), out);
        fwrite(enc, 1, enc_len, out);
        fwrite(tag, 1, tag_len_u, out);
        fclose(out);
        printf("Wrote package %s (ct=%u iv=%u enc=%u tag=%u)\n", out_path, ct_len_u, iv_len_u, enc_len_u, tag_len_u);
    } else {
        /* Send package over UART back to receiver */
        uart uart_dev;
        uart_init(&uart_dev, uart_base);
        unsigned char hdr[16];
        memcpy(hdr + 0, &ct_len_u, 4);
        memcpy(hdr + 4, &iv_len_u, 4);
        memcpy(hdr + 8, &enc_len_u, 4);
        memcpy(hdr + 12, &tag_len_u, 4);
        uart_transmit_string(&uart_dev, (char*)hdr, 16);
        uart_transmit_string(&uart_dev, (char*)ct, ct_len_u);
        uart_transmit_string(&uart_dev, (char*)iv, iv_len_u);
        uart_transmit_string(&uart_dev, (char*)enc, enc_len_u);
        uart_transmit_string(&uart_dev, (char*)tag, tag_len_u);
        printf("Sent package over UART at base 0x%08x\n", uart_base);
    }

    free(pk);
    free(img);
    free(enc);
    free(tag);
    return 0;
}
