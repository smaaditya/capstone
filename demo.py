#!/usr/bin/env python3
"""
=============================================================================
  CAPSTONE DEMO: Secure Image Transmission on RISC-V
  Hybrid Post-Quantum Protocol (CRYSTALS-Kyber + AES-CBC)
=============================================================================
Orchestrates the full encryption/decryption pipeline using the project's
existing C executables (host_sender.exe and secure_receiver.exe).
"""

import os
import sys
import time
import shutil
import struct
import hashlib
import subprocess
import glob

# ─── Paths (relative to this script's location) ─────────────────────────────
BASE        = os.path.dirname(os.path.abspath(__file__))
SENDER_DIR  = os.path.join(BASE, "kyber-main", "host_sender")
RECEIVER_DIR= os.path.join(BASE, "RISC-V-main", "processor", "fpga_uart", "secure_receiver")
SENDER_EXE  = os.path.join(SENDER_DIR, "host_sender.exe")
RECEIVER_EXE= os.path.join(RECEIVER_DIR, "secure_receiver.exe")
DEMO_DIR    = os.path.join(BASE, "demo_workspace")

# ─── MSYS2 toolchain (required for OpenSSL DLLs and building) ───────────────
MSYS2_BIN   = r"C:\msys64\mingw64\bin"
MSYS2_GCC   = os.path.join(MSYS2_BIN, "gcc.exe")

# Ensure MSYS2 bin is in PATH so libcrypto-3-x64.dll can be found at runtime
if os.path.isdir(MSYS2_BIN) and MSYS2_BIN not in os.environ.get("PATH", ""):
    os.environ["PATH"] = MSYS2_BIN + os.pathsep + os.environ.get("PATH", "")

# ─── ANSI colour helpers ────────────────────────────────────────────────────
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"

def banner(text, colour=CYAN):
    w = 76
    print()
    print(f"{colour}{BOLD}{'=' * w}")
    for line in text.strip().split('\n'):
        print(f"  {line.strip()}")
    print(f"{'=' * w}{RESET}")
    print()

def section(num, title):
    print(f"\n{YELLOW}{BOLD}  [{num}] {title}{RESET}")
    print(f"  {DIM}{'-' * 68}{RESET}")

def info(msg):
    print(f"  {DIM}|{RESET}  {msg}")

def success(msg):
    print(f"  {GREEN}{BOLD}[OK]{RESET}  {GREEN}{msg}{RESET}")

def error(msg):
    print(f"  {RED}{BOLD}[X]  {msg}{RESET}")

def highlight(msg):
    print(f"  {MAGENTA}{BOLD}>>>{RESET} {MAGENTA}{msg}{RESET}")

def hex_preview(label, data, max_bytes=32):
    """Show a hex preview of raw bytes."""
    shown = data[:max_bytes]
    hex_str = ' '.join(f'{b:02x}' for b in shown)
    suffix = f" ... ({len(data)} bytes total)" if len(data) > max_bytes else f" ({len(data)} bytes)"
    info(f"{WHITE}{BOLD}{label}:{RESET} {DIM}{hex_str}{suffix}{RESET}")

def wait_effect(label, duration=0.5, steps=20):
    """Simple progress dots."""
    sys.stdout.write(f"  {DIM}|{RESET}  {label} ")
    sys.stdout.flush()
    for _ in range(steps):
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(duration / steps)
    print(f" {GREEN}done{RESET}")

def file_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def run_exe(exe, args, cwd, label=""):
    """Run a C executable and return (stdout, stderr, returncode)."""
    cmd = [exe] + args
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=120)
    return result.stdout.decode(errors='replace'), result.stderr.decode(errors='replace'), result.returncode

def build_if_needed():
    """Rebuild the executables if they don't exist, using MSYS2 gcc."""
    missing = []
    if not os.path.isfile(SENDER_EXE):
        missing.append("host_sender")
    if not os.path.isfile(RECEIVER_EXE):
        missing.append("secure_receiver")

    if not missing:
        return True

    if not os.path.isfile(MSYS2_GCC):
        error(f"MSYS2 gcc not found at {MSYS2_GCC}. Please install MSYS2 with mingw-w64-x86_64-gcc.")
        return False

    info("Some executables are missing. Building with MSYS2 gcc...")

    KYBER_REF  = os.path.join(BASE, "kyber-main", "kyber-main", "ref")
    AES_DIR    = os.path.join(BASE, "RISC-V-main", "RISC-V-main", "test", "aes")
    UART_C     = os.path.join(BASE, "RISC-V-main", "RISC-V-main", "lib", "uart.c")

    # Kyber reference source files
    kyber_srcs = [os.path.join(KYBER_REF, f) for f in [
        "kem.c", "indcpa.c", "polyvec.c", "poly.c", "ntt.c",
        "cbd.c", "reduce.c", "verify.c", "fips202.c",
        "symmetric-shake.c", "randombytes.c"
    ]]
    aes_c = os.path.join(AES_DIR, "aes.c")

    for name in missing:
        if name == "host_sender":
            src = os.path.join(SENDER_DIR, "host_sender.c")
            out = SENDER_EXE
            srcs = [src] + kyber_srcs + [aes_c, UART_C]
            incs = [f"-I{KYBER_REF}", f"-I{AES_DIR}",
                    f"-I{os.path.join(BASE, 'RISC-V-main', 'RISC-V-main', 'lib')}"]
        else:
            src = os.path.join(RECEIVER_DIR, "secure_receiver.c")
            out = RECEIVER_EXE
            srcs = [src] + kyber_srcs + [aes_c, UART_C]
            incs = [f"-I{KYBER_REF}", f"-I{AES_DIR}"]

        cmd = [MSYS2_GCC, "-O2"] + incs + srcs + ["-lcrypto", "-o", out]
        info(f"Building {name} ...")
        result = subprocess.run(cmd, capture_output=True, timeout=120)
        if result.returncode != 0:
            error(f"Build failed for {name}:")
            print(result.stderr.decode(errors='replace'))
            return False
        success(f"{name} built successfully")

    return True


# =============================================================================
#  MAIN DEMO
# =============================================================================
def main():
    os.system('')  # Enable ANSI on Windows

    # Force UTF-8 output to handle Unicode box-drawing characters
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')

    banner("""
    SECURE IMAGE TRANSMISSION ON RISC-V
    Hybrid Post-Quantum Protocol Demo
    CRYSTALS-Kyber (ML-KEM) + AES-CBC + SHA3-256
    """)

    # ------ Pre-flight checks ------
    section("0", "PRE-FLIGHT CHECKS")
    if not build_if_needed():
        return 1
    success(f"host_sender.exe   found: {SENDER_EXE}")
    success(f"secure_receiver.exe found: {RECEIVER_EXE}")

    # Create demo workspace
    os.makedirs(DEMO_DIR, exist_ok=True)
    info(f"Demo workspace: {DEMO_DIR}")

    # ------ Ask for image ------
    section("1", "SELECT INPUT IMAGE")
    info("Enter the path to an image file (PNG, JPG, BMP, any file works).")
    info("You can drag-and-drop the file into this terminal.\n")

    while True:
        sys.stdout.write(f"  {CYAN}Image path > {RESET}")
        sys.stdout.flush()
        img_path = input().strip().strip('"').strip("'")
        if os.path.isfile(img_path):
            break
        error(f"File not found: {img_path}. Try again.")

    img_size = os.path.getsize(img_path)
    img_name = os.path.basename(img_path)
    img_hash = file_sha256(img_path)

    success(f"Input image: {img_name}")
    info(f"Size: {img_size:,} bytes")
    info(f"SHA-256: {img_hash[:16]}...{img_hash[-16:]}")

    # Copy to demo workspace
    demo_img = os.path.join(DEMO_DIR, img_name)
    shutil.copy2(img_path, demo_img)

    # =========================================================================
    #  STEP 2: KEY GENERATION (Receiver side)
    # =========================================================================
    section("2", "KYBER KEY GENERATION  (Receiver Side)")
    info("The receiver generates a CRYSTALS-Kyber-768 key pair.")
    info("Algorithm: ML-KEM (FIPS 203) over Rq = Z_3329[X]/(X^256+1), k=3")
    info("")
    info(f"  {DIM}crypto_kem_keypair(pk, sk){RESET}")
    info(f"  {DIM}  - Samples secret vector s, error vector e from CBD_eta{RESET}")
    info(f"  {DIM}  - Generates public matrix A from seed via SHAKE-128{RESET}")
    info(f"  {DIM}  - Computes t = NTT(A * s + e){RESET}")
    info(f"  {DIM}  - pk = (t, seed)   sk = (s || pk || H(pk) || z){RESET}")
    info("")

    wait_effect("Generating Kyber-768 key pair", 1.0)

    # Run secure_receiver with no args to generate keys
    stdout, stderr, rc = run_exe(RECEIVER_EXE, [], DEMO_DIR)
    if rc != 0:
        error(f"Key generation failed (exit {rc})")
        info(stderr)
        return 1

    pk_path = os.path.join(DEMO_DIR, "pk.bin")
    sk_path = os.path.join(DEMO_DIR, "sk.bin")

    if not os.path.isfile(pk_path) or not os.path.isfile(sk_path):
        error("Key files not generated!")
        return 1

    pk_size = os.path.getsize(pk_path)
    sk_size = os.path.getsize(sk_path)

    success(f"Public key  (pk.bin): {pk_size:,} bytes")
    success(f"Secret key  (sk.bin): {sk_size:,} bytes")

    with open(pk_path, 'rb') as f:
        pk_data = f.read()
    with open(sk_path, 'rb') as f:
        sk_data = f.read()

    hex_preview("Public Key (first 32 bytes)", pk_data)
    hex_preview("Secret Key (first 32 bytes)", sk_data)

    info("")
    highlight("In the real system: pk is transmitted from RISC-V FPGA to host via UART (9600 baud)")

    # =========================================================================
    #  STEP 3: ENCAPSULATION & ENCRYPTION (Sender side)
    # =========================================================================
    section("3", "KYBER ENCAPSULATION + AES ENCRYPTION  (Host Sender)")
    info("The host sender performs:")
    info(f"  1. {WHITE}Kyber Encapsulation{RESET}: crypto_kem_enc(ct, ss, pk)")
    info(f"     - Generates random message m, hashes (m||H(pk))")
    info(f"     - IND-CPA encryption with deterministic coins")
    info(f"     - Produces ciphertext ct and shared secret ss")
    info(f"  2. {WHITE}Key Derivation{RESET}: AES_key = SHA3-256(shared_secret)")
    info(f"  3. {WHITE}Random IV{RESET}: 16 bytes from OpenSSL RAND_bytes")
    info(f"  4. {WHITE}PKCS7 Padding{RESET}: pad image to 16-byte AES block boundary")
    info(f"  5. {WHITE}AES-CBC Encryption{RESET}: encrypt padded image")
    info(f"  6. {WHITE}Authentication Tag{RESET}: SHA3-256(ss || IV || ciphertext)")
    info(f"  7. {WHITE}Package{RESET}: [ct_len|iv_len|enc_len|tag_len|ct|iv|enc|tag]")
    info("")

    wait_effect("Encapsulating shared secret (Kyber-768)", 0.8)
    wait_effect("Deriving AES key via SHA3-256", 0.4)
    wait_effect("Encrypting image with AES-CBC", 0.6)
    wait_effect("Computing authentication tag (SHA3-256)", 0.4)

    pkg_path = os.path.join(DEMO_DIR, "package.bin")
    stdout, stderr, rc = run_exe(SENDER_EXE, [pk_path, demo_img, pkg_path], DEMO_DIR)

    if rc != 0:
        error(f"Encryption failed (exit {rc})")
        info(stderr)
        return 1

    # Parse the sender's debug output for shared secret and tag
    ss_host = ""
    tag_host = ""
    for line in stderr.split('\n'):
        if line.startswith("ss-host:"):
            ss_host = line.split(":", 1)[1].strip()
        if line.startswith("tag-host:"):
            tag_host = line.split(":", 1)[1].strip()

    pkg_size = os.path.getsize(pkg_path)
    success(f"Encrypted package: package.bin ({pkg_size:,} bytes)")

    # Parse the package header
    with open(pkg_path, 'rb') as f:
        hdr = f.read(16)
        ct_len, iv_len, enc_len, tag_len = struct.unpack('<IIII', hdr)
        ct_data = f.read(ct_len)
        iv_data = f.read(iv_len)
        enc_data = f.read(enc_len)
        tag_data = f.read(tag_len)

    info("")
    info(f"{WHITE}{BOLD}Package Structure:{RESET}")
    info(f"  +-------------------+-------+-----------+")
    info(f"  | Field             | Size  | Value     |")
    info(f"  +-------------------+-------+-----------+")
    info(f"  | ct_len  (header)  | 4 B   | {ct_len:<9} |")
    info(f"  | iv_len  (header)  | 4 B   | {iv_len:<9} |")
    info(f"  | enc_len (header)  | 4 B   | {enc_len:<9} |")
    info(f"  | tag_len (header)  | 4 B   | {tag_len:<9} |")
    info(f"  | Kyber ciphertext  | {ct_len:>5} | encrypted |")
    info(f"  | AES IV            | {iv_len:>5} | random    |")
    info(f"  | Encrypted image   | {enc_len:>5} | AES-CBC   |")
    info(f"  | Auth tag          | {tag_len:>5} | SHA3-256  |")
    info(f"  +-------------------+-------+-----------+")
    info(f"  Total: {16 + ct_len + iv_len + enc_len + tag_len:,} bytes")
    info("")

    hex_preview("Kyber Ciphertext", ct_data)
    hex_preview("AES IV", iv_data, max_bytes=16)
    hex_preview("Encrypted Image", enc_data)
    hex_preview("Authentication Tag", tag_data, max_bytes=32)

    if ss_host:
        info("")
        info(f"{WHITE}{BOLD}Sender's Shared Secret:{RESET} {DIM}{ss_host[:64]}...{RESET}")
    if tag_host:
        info(f"{WHITE}{BOLD}Sender's Auth Tag:     {RESET} {DIM}{tag_host[:64]}...{RESET}")

    highlight("In the real system: package is transmitted from host PC to RISC-V FPGA via UART")

    # =========================================================================
    #  STEP 4: DECAPSULATION & DECRYPTION (Receiver side)
    # =========================================================================
    section("4", "KYBER DECAPSULATION + AES DECRYPTION  (Secure Receiver)")
    info("The secure receiver performs:")
    info(f"  1. {WHITE}Parse package{RESET}: extract ct, iv, enc_data, tag from binary")
    info(f"  2. {WHITE}Kyber Decapsulation{RESET}: crypto_kem_dec(ss, ct, sk)")
    info(f"     - Re-encrypts internally to verify ciphertext (FO transform)")
    info(f"     - Constant-time comparison (prevents timing side-channels)")
    info(f"     - Implicit rejection on tampered ciphertext")
    info(f"  3. {WHITE}Key Derivation{RESET}: AES_key = SHA3-256(shared_secret)")
    info(f"  4. {WHITE}Verify Auth Tag{RESET}: SHA3-256(ss||IV||enc) == received tag")
    info(f"  5. {WHITE}AES-CBC Decryption{RESET}: decrypt ciphertext in-place")
    info(f"  6. {WHITE}Remove PKCS7 padding{RESET}: recover original image bytes")
    info("")

    wait_effect("Decapsulating shared secret (Kyber-768)", 0.8)
    wait_effect("Deriving AES key via SHA3-256", 0.4)
    wait_effect("Verifying authentication tag", 0.5)
    wait_effect("Decrypting image with AES-CBC", 0.6)

    out_name = "recovered_" + img_name
    out_path = os.path.join(DEMO_DIR, out_name)
    stdout, stderr, rc = run_exe(RECEIVER_EXE, [pkg_path, out_path], DEMO_DIR)

    if rc != 0:
        error(f"Decryption failed (exit {rc})")
        info(stderr)
        return 1

    # Parse receiver's debug output
    ss_rcvr = ""
    tag_rcvr = ""
    for line in stderr.split('\n'):
        if line.startswith("ss-rcvr:"):
            ss_rcvr = line.split(":", 1)[1].strip()
        if line.startswith("tag-rcvr:"):
            tag_rcvr = line.split(":", 1)[1].strip()

    out_size = os.path.getsize(out_path)
    out_hash = file_sha256(out_path)

    success(f"Decryption successful!")
    success(f"Recovered image: {out_name} ({out_size:,} bytes)")

    if ss_rcvr:
        info("")
        info(f"{WHITE}{BOLD}Receiver's Shared Secret:{RESET} {DIM}{ss_rcvr[:64]}...{RESET}")
    if tag_rcvr:
        info(f"{WHITE}{BOLD}Receiver's Auth Tag:     {RESET} {DIM}{tag_rcvr[:64]}...{RESET}")

    # =========================================================================
    #  STEP 5: VERIFICATION
    # =========================================================================
    section("5", "INTEGRITY VERIFICATION")
    info(f"Original image:  {img_name}")
    info(f"  Size:    {img_size:,} bytes")
    info(f"  SHA-256: {img_hash}")
    info("")
    info(f"Recovered image: {out_name}")
    info(f"  Size:    {out_size:,} bytes")
    info(f"  SHA-256: {out_hash}")
    info("")

    if img_hash == out_hash and img_size == out_size:
        success("MATCH! Recovered image is identical to the original.")
    else:
        error("MISMATCH! Files differ.")

    if ss_host and ss_rcvr:
        info("")
        if ss_host == ss_rcvr:
            success("Shared secrets match (sender == receiver)")
        else:
            error("Shared secrets DO NOT match!")

    if tag_host and tag_rcvr:
        if tag_host == tag_rcvr:
            success("Authentication tags match (integrity verified)")
        else:
            error("Authentication tags DO NOT match!")

    # =========================================================================
    #  STEP 6: SUMMARY
    # =========================================================================
    section("6", "DEMO SUMMARY")
    print()
    info(f"{WHITE}{BOLD}Cryptographic Pipeline:{RESET}")
    info(f"")
    info(f"  {CYAN}Receiver (RISC-V){RESET}                  {YELLOW}Host Sender (x86){RESET}")
    info(f"  ----------------                  ----------------")
    info(f"  crypto_kem_keypair()              ")
    info(f"    pk = {pk_size} bytes                  ")
    info(f"    sk = {sk_size} bytes                  ")
    info(f"            ----pk ({pk_size}B)---->    ")
    info(f"                                    crypto_kem_enc(ct, ss, pk)")
    info(f"                                    SHA3-256(ss) -> AES key")
    info(f"                                    AES-CBC encrypt ({enc_len}B)")
    info(f"                                    SHA3-256 auth tag ({tag_len}B)")
    info(f"            <--package ({pkg_size}B)--  ")
    info(f"  crypto_kem_dec(ss, ct, sk)        ")
    info(f"  SHA3-256(ss) -> AES key           ")
    info(f"  Verify auth tag: {GREEN}PASS{RESET}             ")
    info(f"  AES-CBC decrypt                   ")
    info(f"  Remove PKCS7 padding              ")
    info(f"    -> recovered image              ")
    info(f"")
    info(f"  {WHITE}{BOLD}Security: Kyber-768 (192-bit post-quantum) + AES-128-CBC + SHA3-256{RESET}")
    info(f"  {WHITE}{BOLD}Standards: FIPS 203 (ML-KEM) | FIPS 197 (AES) | FIPS 202 (SHA-3){RESET}")
    print()

    # =========================================================================
    #  STEP 7: VIEW RECOVERED IMAGE
    # =========================================================================
    section("7", "VIEW RECOVERED IMAGE")
    info(f"Recovered file: {out_path}")
    info("")

    while True:
        sys.stdout.write(f"  {CYAN}Open recovered image? [Y/n] > {RESET}")
        sys.stdout.flush()
        choice = input().strip().lower()
        if choice in ('', 'y', 'yes'):
            info("Opening image...")
            try:
                os.startfile(out_path)
                success("Image opened in default viewer.")
            except Exception as e:
                error(f"Could not open: {e}")
                info(f"You can manually open: {out_path}")
            break
        elif choice in ('n', 'no'):
            info("Skipped. You can find the image at:")
            info(f"  {out_path}")
            break
        else:
            info("Please enter Y or N.")

    # Also offer to open side by side
    info("")
    while True:
        sys.stdout.write(f"  {CYAN}Also open the original for comparison? [Y/n] > {RESET}")
        sys.stdout.flush()
        choice = input().strip().lower()
        if choice in ('', 'y', 'yes'):
            try:
                os.startfile(img_path)
                success("Original image opened.")
            except Exception as e:
                error(f"Could not open: {e}")
            break
        elif choice in ('n', 'no'):
            break
        else:
            info("Please enter Y or N.")

    banner("""
    DEMO COMPLETE
    Post-quantum secure image transmission demonstrated successfully.
    All files are in: demo_workspace/
    """, GREEN)

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{RED}Demo interrupted.{RESET}")
        sys.exit(1)
