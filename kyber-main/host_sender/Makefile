
CC = gcc
# include path to the ref/ folder under the top-level kyber-main
CFLAGS = -O2 -I../kyber-main/ref -I../../RISC-V-main/RISC-V-main/test/aes
LDFLAGS = -lcrypto

AES_SRC = ../../RISC-V-main/RISC-V-main/test/aes/aes.c
UART_SRC = ../../RISC-V-main/RISC-V-main/lib/uart.c

all:
	$(CC) $(CFLAGS) host_sender.c ../kyber-main/ref/*.c $(AES_SRC) $(UART_SRC) -o host_sender $(LDFLAGS)

clean:
	rm -f host_sender
