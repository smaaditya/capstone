Secure Receiver (RISC-V / host testing)
=====================================

This small program implements the Receiver side of your "secure image transmission" flow using the Kyber ref implementation for KEM and OpenSSL AES for testing on host.

The C source also defines preprocessor macros that map the generic `crypto_kem_*`
names and `CRYPTO_*` size constants to the Kyber‑512 reference implementation. You
can change the macros in the source if you wish to target Kyber‑768 or -1024.

What it does:
- Generates a Kyber keypair and writes `pk.bin` and `sk.bin` in the current directory.
- Waits for a package file produced by the sender (format described in kyber-main/host_sender/README.md).
- Decapsulates the Kyber ciphertext to recover the shared secret, derives a 32-byte AES key using `SHA3-256(ss)`, verifies a 32-byte SHA3-256 authentication tag, and AES-decrypts the image.

Build & test on host:

    cd RISC-V-main/processor/fpga_uart/secure_receiver
    make all-host
    ./secure_receiver              # generates pk.bin and sk.bin

Copy `pk.bin` to the host sender (or run kyber-main/host_sender/host_sender using the produced pk.bin).
When the sender has produced `package.bin`, run:

    ./secure_receiver package.bin recovered.img

Notes for deployment to the RISC-V soft-core:
- The program currently uses OpenSSL for AES decrypt for convenience. On the RISC-V target, replace the AES calls with a portable AES implementation (the repo contains small AES test code under `RISC-V-main/test/aes/`).
- The program writes `pk.bin` and `sk.bin`; in a deployed Receiver you would send `pk.bin` over UART to the Sender and use UART to receive the package bytes.
- Key derivation and tag use SHA3 per Kyber/NIST usage: `SHA3-256(ss)` for AES key and `SHA3-256(ss||IV||EncImg)` for authentication tag.

UART / cross-deploy notes:

- File-mode demo (host):

    cd RISC-V-main/processor/fpga_uart/secure_receiver
    make all-host
    ./secure_receiver            # writes pk.bin

    cd ../../../../kyber-main/host_sender
    make
    ./host_sender ../RISC-V-main/processor/fpga_uart/secure_receiver/pk.bin image.png package.bin

    cd RISC-V-main/processor/fpga_uart/secure_receiver
    ./secure_receiver package.bin recovered.png

- UART/demo mode (simulation or real HW using memory-mapped UART):

  1. Start receiver in UART mode on the target (or simulation); example using base `0x10000000`:

      ./secure_receiver uart 0x10000000 recovered.png

  2. Start host sender in UART mode (matching base):

      cd kyber-main/host_sender
      ./host_sender uart 0x10000000 image.png

  The receiver will transmit its `pk` over UART, the host will encapsulate and return the package over UART, and the receiver will decapsulate and recover the image.

- Cross-compile and ROM image generation:

  1. Cross-compile (adjust toolchain name/path if needed):

      make cross

  2. Create binary and ROM image (on host):

      riscv32-unknown-elf-objcopy -O binary secure_receiver.elf secure_receiver.bin
      gcc -O2 -o rom_generator ../../../../test/rom_generator.c
      ./rom_generator secure_receiver.bin > secure_receiver.mem

  Place `secure_receiver.mem` into the BRAM initializer for your `fpga_top.v` or testbench.
