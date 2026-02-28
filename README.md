# Capstone Demonstration

This repository contains two sub‑projects used in the capstone: a reference
implementation of the Kyber post‑quantum key‑encapsulation scheme and a simple
UART‑based secure sender/receiver running on a RISC‑V core.

## Repository layout

```
capstone/
├─ kyber-main/            # NIST PQC code (with a small host sender tool)
│   ├─ host_sender/       # program that encrypts an image/package using
│   │   ├─ host_sender.c   #   Kyber + AES + UART support
│   │   └─ Makefile
│   └─ kyber-main/        # upstream Kyber reference sources (ref/, avx2/ ...)
└─ RISC-V-main/           # RISC‑V processor and peripherals
    └─ processor/fpga_uart/secure_receiver/
        ├─ secure_receiver.c  # companion program reading the package
        └─ Makefile
``` 

The host sender and secure receiver communicate by exchanging files or,
optionally, via a UART memory‑mapped peripheral (used when running on an
FPGA/RTL model).

## Prerequisites

* MSYS2/MinGW environment on Windows.
* A test image file (e.g. `image.png`) to encrypt.

### Installing build tools in MSYS2

If this is your first time, install the necessary development tools and libraries:

```sh
pacman -Syu                  # update package database
pacman -S gcc                # GCC compiler (MSYS native)
pacman -S openssl-devel      # OpenSSL dev libraries
pacman -S make               # GNU Make
```

After installation, close and reopen your MSYS shell. Verify everything is ready:

```sh
gcc --version
make --version
```

Both should report version numbers. If `gcc` is still not found, you may have
installed the MinGW version instead of the MSYS version. Check which version
is installed:

```sh
pacman -Qi gcc
```

If it says `Architecture: x86_64-w64-mingw32`, uninstall it and use the MSYS
native version:

```sh
pacman -R mingw-w64-x86_64-gcc
pacman -S gcc openssl-devel make
```

## Building the tools

Open an MSYS/bash shell and run the following commands:

```sh
# Start in workspace root
cd /c/Users/Mithun/capstone

# Build the host-side sender program
cd kyber-main/host_sender
make              # produces ./host_sender

# Build the host-side receiver program
cd ../../RISC-V-main/processor/fpga_uart/secure_receiver
make all-host     # produces ./secure_receiver
```

The receiver Makefile also supports `make cross` to compile a RISC‑V binary
(`secure_receiver.elf`) that can be loaded into an FPGA/CPU model.

## Demonstration workflow

1. **Generate a keypair on the receiver**

   ```sh
   cd /c/Users/Mithun/capstone/RISC-V-main/processor/fpga_uart/secure_receiver
   ./secure_receiver
   # Output: pk.bin and sk.bin are created in this directory
   ```

2. **Encrypt an image using the host sender**

   ```sh
   cd /c/Users/Mithun/capstone/kyber-main/host_sender
   ./host_sender ../../RISC-V-main/processor/fpga_uart/secure_receiver/pk.bin \
                  image.png package.bin
   # package.bin will be written here
   ```

   *`image.png` may be any file you wish to protect.*

3. **Decrypt the package on the receiver**

   ```sh
   cd /c/Users/Mithun/capstone/RISC-V-main/processor/fpga_uart/secure_receiver
   ./secure_receiver ../../../../kyber-main/host_sender/package.bin recovered.png
   ```

   `recovered.png` should match the original `image.png` (byte‑for‑byte).

### Alternative: copy keys/files instead of using relative paths
Just copy `pk.bin` or `package.bin` between directories if the deep
relative paths are confusing.

## UART mode (optional)

The two programs support exchanging data over a memory‑mapped UART device
instead of using files.  This is useful when the receiver runs on actual
hardware or an RTL model with a UART peripheral.

1. Run the receiver in UART receive mode:

   ```sh
   cd .../secure_receiver
   ./secure_receiver uart 0x10000000 recovered.png
   ```

   (the first invocation generates keys and listens for a package on the
   UART base address 0x10000000).

2. In a separate shell, run the sender to transmit a public key and image:

   ```sh
   cd .../host_sender
   ./host_sender uart 0x10000000 image.png
   ```

   The sender will push the generated package back over UART and the
   receiver will decrypt it.

*Change the base address if your hardware uses a different UART register
map.*

## Cleaning up

```sh
cd kyber-main/host_sender && make clean
cd ../../RISC-V-main/processor/fpga_uart/secure_receiver && make clean
``` 

## Notes & troubleshooting

* Always provide correct paths.  `host_sender` writes `package.bin` to its
  current directory; `secure_receiver` attempts to open whatever name you
  pass to it, so run it from the directory where that file actually resides
  or specify an absolute/relative path.
* If you see `ERROR: failed to read pk file` or `failed to open package file`,
  the program simply could not find the file at the path you gave it.
* The RSA code in `kyber-main/kyber-main/ref` is unmodified from the official
  NIST submission; this project merely wraps it to demonstrate a simple
  usage with AES and UART transport.

## Version control

This workspace is under git; the first commit was made after copying the
source tree.  Feel free to add your own branches or tag points of progress.

---

With the above steps you can compile, run, and demonstrate the complete
host/receiver encryption workflow using the provided code.  Enjoy!
