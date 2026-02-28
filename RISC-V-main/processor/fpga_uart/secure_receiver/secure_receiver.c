/*
 * Secure Receiver (simulation-friendly):
 * - generates Kyber keypair (writes pk.bin and sk.bin)
 * - waits for package file (from Sender) and decrypts it
 * - outputs recovered image to disk
 *
 * Build for host (quick test): `gcc -O2 secure_receiver.c ../../../../kyber-main/ref/*.c -I../../../../kyber-main/ref -lcrypto -o secure_receiver`
 * For cross-compiling to RISC-V, use your riscv toolchain and replace OpenSSL AES calls with a lightweight AES implementation available on-target.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../../../../kyber-main/kyber-main/ref/api.h"
#include "../../../../kyber-main/kyber-main/ref/kem.h"
#include "../../../../kyber-main/kyber-main/ref/fips202.h"

// Use CRYPTO_* constants provided by the Kyber ref headers (no redefinition)
/* Keep the ref implementation's standard `crypto_kem_*` function names so
    they link against the definitions in the ref sources (kem.c). */
#include "../../../../RISC-V-main/RISC-V-main/test/aes/aes.h"
#include "../../../../RISC-V-main/RISC-V-main/lib/uart.h"

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
    int use_uart = 0;
    const char *pkg_path = NULL;
    const char *out_img = NULL;
    uint32_t uart_base = 0;

    if (argc < 2) {
        /* No args: generate and write keypair for sender to use */
        unsigned char pk[CRYPTO_PUBLICKEYBYTES];
        unsigned char sk[CRYPTO_SECRETKEYBYTES];
        if (crypto_kem_keypair(pk, sk) != 0) handle_errors("crypto_kem_keypair failed");

        FILE *fpk = fopen("pk.bin", "wb");
        if (!fpk) handle_errors("failed to open pk.bin for write");
        fwrite(pk, 1, CRYPTO_PUBLICKEYBYTES, fpk);
        fclose(fpk);
        FILE *fsk = fopen("sk.bin", "wb");
        if (!fsk) handle_errors("failed to open sk.bin for write");
        fwrite(sk, 1, CRYPTO_SECRETKEYBYTES, fsk);
        fclose(fsk);

        printf("Generated keypair. Wrote pk.bin (%d bytes) and sk.bin (%d bytes).\n", CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES);
        printf("Send pk.bin to Sender (e.g. host_sender) and produce a package file.\n");
        printf("Usage for file mode: ./secure_receiver <package_file> <output_image>\n");
        printf("Usage for UART mode: ./secure_receiver uart <uart_base_hex> <output_image>\n");
        return 0;
    }

    /* Determine mode */
    if (argc >= 2 && strcmp(argv[1], "uart") == 0) {
        if (argc != 4) { fprintf(stderr, "uart mode expects: uart <base_hex> <out_img>\n"); return 1; }
        use_uart = 1;
        uart_base = (uint32_t)strtoul(argv[2], NULL, 0);
        out_img = argv[3];
    } else {
        if (argc != 3) { fprintf(stderr, "file mode expects: <package_file> <out_img>\n"); return 1; }
        pkg_path = argv[1];
        out_img = argv[2];
    }

    /* read package either from file or UART */
    uint32_t ct_len_u = 0, iv_len_u = 0, enc_len_u = 0, tag_len_u = 0;
    unsigned char *ct = NULL, *iv = NULL, *enc = NULL, *tag = NULL;
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];

    if (!use_uart) {
        /* for file mode we must read the receiver's secret key in order to decapsulate */
        FILE *fsk = fopen("sk.bin", "rb");
        if (!fsk) handle_errors("failed to open sk.bin");
        if (fread(sk,1,CRYPTO_SECRETKEYBYTES,fsk) != CRYPTO_SECRETKEYBYTES) handle_errors("failed to read sk.bin");
        fclose(fsk);

        FILE *pkg = fopen(pkg_path, "rb");
        if (!pkg) handle_errors("failed to open package file");
        fread(&ct_len_u, sizeof(ct_len_u), 1, pkg);
        fread(&iv_len_u, sizeof(iv_len_u), 1, pkg);
        fread(&enc_len_u, sizeof(enc_len_u), 1, pkg);
        fread(&tag_len_u, sizeof(tag_len_u), 1, pkg);
        ct = malloc(ct_len_u); iv = malloc(iv_len_u); enc = malloc(enc_len_u); tag = malloc(tag_len_u);
        if (!ct || !iv || !enc || !tag) handle_errors("memory alloc failed");
        if (fread(ct, 1, ct_len_u, pkg) != ct_len_u) handle_errors("failed to read ct");
        if (fread(iv, 1, iv_len_u, pkg) != iv_len_u) handle_errors("failed to read iv");
        if (fread(enc, 1, enc_len_u, pkg) != enc_len_u) handle_errors("failed to read enc image");
        if (fread(tag, 1, tag_len_u, pkg) != tag_len_u) handle_errors("failed to read tag");
        fclose(pkg);
    } else {
        /* UART mode: initialize uart and stream-in header and payload */
        uart uart_dev;
        uart_init(&uart_dev, uart_base);
        /* Send public key length and public key to remote sender */
        uint32_t pk_len_u = CRYPTO_PUBLICKEYBYTES;
        unsigned char pk_hdr[4];
        memcpy(pk_hdr, &pk_len_u, 4);
        uart_transmit_string(&uart_dev, (char*)pk_hdr, 4);
        uart_transmit_string(&uart_dev, (char*)pk, pk_len_u);
        unsigned char hdr[16];
        /* read 4 x uint32 fields */
        if (uart_receive(&uart_dev, hdr, 16) != 16) handle_errors("failed to read header via uart");
        ct_len_u = *((uint32_t*)(hdr + 0));
        iv_len_u = *((uint32_t*)(hdr + 4));
        enc_len_u = *((uint32_t*)(hdr + 8));
        tag_len_u = *((uint32_t*)(hdr + 12));
        ct = malloc(ct_len_u); iv = malloc(iv_len_u); enc = malloc(enc_len_u); tag = malloc(tag_len_u);
        if (!ct || !iv || !enc || !tag) handle_errors("memory alloc failed");
        if (uart_receive(&uart_dev, ct, ct_len_u) != ct_len_u) handle_errors("failed to read ct via uart");
        if (uart_receive(&uart_dev, iv, iv_len_u) != iv_len_u) handle_errors("failed to read iv via uart");
        if (uart_receive(&uart_dev, enc, enc_len_u) != enc_len_u) handle_errors("failed to read enc via uart");
        if (uart_receive(&uart_dev, tag, tag_len_u) != tag_len_u) handle_errors("failed to read tag via uart");
    }

    /* decapsulate */
    unsigned char ss[CRYPTO_BYTES];
    if (crypto_kem_dec(ss, ct, sk) != 0) handle_errors("crypto_kem_dec failed");
    print_hex("ss-rcvr", ss, CRYPTO_BYTES);

    /* Derive AES key from SHA3-256 and truncate to AES_KEYLEN */
    unsigned char full_hash[32];
    sha3_256(full_hash, ss, CRYPTO_BYTES);
    unsigned char aes_key[AES_KEYLEN];
    memcpy(aes_key, full_hash, AES_KEYLEN);

    /* Verify authentication tag (SHA3-256 over ss||iv||enc) */
    unsigned char *tag_input = malloc(CRYPTO_BYTES + iv_len_u + enc_len_u);
    if (!tag_input) handle_errors("alloc failed");
    memcpy(tag_input, ss, CRYPTO_BYTES);
    memcpy(tag_input + CRYPTO_BYTES, iv, iv_len_u);
    memcpy(tag_input + CRYPTO_BYTES + iv_len_u, enc, enc_len_u);
    unsigned char computed_tag[32];
    sha3_256(computed_tag, tag_input, (unsigned long long)(CRYPTO_BYTES + iv_len_u + enc_len_u));
    print_hex("tag-rcvr", computed_tag, 32);
    free(tag_input);

    if (tag_len_u != 32) handle_errors("unexpected tag length");
    if (memcmp(computed_tag, tag, 32) != 0) handle_errors("authentication tag mismatch — aborting");

    /* Decrypt using repo AES (CBC) */
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aes_key, iv);
    /* AES_CBC_decrypt_buffer works in-place; ensure enc buffer length is multiple of AES_BLOCKLEN */
    if ((enc_len_u % AES_BLOCKLEN) != 0) handle_errors("enc length not multiple of AES_BLOCKLEN");
    AES_CBC_decrypt_buffer(&ctx, enc, enc_len_u);

    /* Remove PKCS7 padding */
    if (enc_len_u == 0) handle_errors("empty decrypted buffer");
    unsigned char pad_val = enc[enc_len_u - 1];
    if (pad_val == 0 || pad_val > AES_BLOCKLEN) handle_errors("invalid padding");
    size_t plain_len = enc_len_u - pad_val;
    unsigned char *plain = malloc(plain_len);
    if (!plain) handle_errors("malloc failed");
    memcpy(plain, enc, plain_len);

    FILE *out = fopen(out_img, "wb");
    if (!out) handle_errors("failed to open output image");
    fwrite(plain, 1, plain_len, out);
    fclose(out);

    printf("Successfully recovered image to %s (size=%zu)\n", out_img, plain_len);

    free(ct); free(iv); free(enc); free(plain);
    return 0;
}
