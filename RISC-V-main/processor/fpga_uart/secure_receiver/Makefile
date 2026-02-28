
HOST_CC = gcc
RISCV_CC = riscv32-unknown-elf-gcc
CFLAGS = -O2 -I../../../../kyber-main/kyber-main/ref -I../../../../RISC-V-main/RISC-V-main/test/aes
LDFLAGS = -lcrypto

AES_SRC = ../../../../RISC-V-main/RISC-V-main/test/aes/aes.c
UART_SRC = ../../../../RISC-V-main/RISC-V-main/lib/uart.c

all-host:
	$(HOST_CC) $(CFLAGS) secure_receiver.c ../../../../kyber-main/kyber-main/ref/*.c $(AES_SRC) $(UART_SRC) -o secure_receiver $(LDFLAGS)

clean:
	rm -f secure_receiver secure_receiver.elf secure_receiver.bin secure_receiver.mem

cross:
	@echo "Cross-build (adjust RISCV toolchain path if necessary)"
	$(RISCV_CC) -march=rv32im -mabi=ilp32 -O2 secure_receiver.c ../../../../kyber-main/kyber-main/ref/*.c $(AES_SRC) -I../../../../kyber-main/kyber-main/ref -o secure_receiver.elf

	@echo "To make a .bin and .mem for ROM init, run (host):"
	@echo "  riscv32-unknown-elf-objcopy -O binary secure_receiver.elf secure_receiver.bin"
	@echo "  gcc -O2 -o rom_generator ../../../../RISC-V-main/RISC-V-main/test/rom_generator.c"
	@echo "  ./rom_generator secure_receiver.bin > secure_receiver.mem"
