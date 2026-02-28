Host Sender
===========

Build (host machine with OpenSSL installed):

    cd kyber-main/host_sender
    # makefile now uses the nested kyber-main/kyber-main/ref path and
    # compiler constants are mapped to Kyber512 by default via macros
    make

Usage:

File mode (fast test):

    ./host_sender <pk.bin> <image_in> <package_out>

Note: `image_in` can be any binary file (PNG, firmware, etc.).
You must provide the correct path to the file – if you copy an image into the
receiver directory, either run the sender from that same directory or specify an
absolute/relative path pointing to it. The program prints the input file size
on startup to help diagnose mistakes.

UART mode (direct sender ↔ receiver over memory-mapped UART in simulation/hardware):

    ./host_sender uart <uart_base_hex> <image_in>

In UART mode the program expects a Receiver core to send its public key over the memory-mapped UART at `uart_base_hex` (4-byte length followed by `pk`); the sender will encapsulate, produce the package and transmit the package back over the same UART.

- `<pk.bin>`: public key file produced by the Receiver (binary).
- `<image_in>`: plaintext image file to encrypt.
- `<package_out>`: output package which contains ciphertext, IV and AES-encrypted image.

The package format:
- 4 bytes: uint32_t ciphertext length (little-endian)
- 4 bytes: uint32_t IV length
- 4 bytes: uint32_t encrypted image length
- 4 bytes: uint32_t authentication tag length
- ciphertext bytes (CRYPTO_CIPHERTEXTBYTES)
- IV bytes (16 bytes)
- encrypted image bytes
- authentication tag (32 bytes) — SHA3-256 over (shared_secret || IV || EncImg)

Note: This program calls the generic `crypto_kem_*` interface, which is
mapped via preprocessor macros to the Kyber‑512 reference implementation in
`../kyber-main/kyber-main/ref`. If you wish to use Kyber‑768 or -1024 adjust
those macros or include the appropriate `pqcrystals_kyber***` symbols.
