#include <stdlib.h>
#include <stdint.h>
#define UART_RX_ADDR_OFFSET 0x1
#define UART_STATUS_ADDR_OFFSET 0x2

typedef struct uart
{
    uintptr_t base_addr;   /* store numeric base address, cast when accessing */
}uart;


void uart_init(uart *uart_ptr, uint32_t base_addr);
void uart_transmit_byte(uart *uart_ptr, const char data);
void uart_transmit_string(uart *uart_ptr, char const *data, size_t len);
char uart_receive_byte(uart *uart_ptr);
size_t uart_receive(uart *uart_ptr, unsigned char *buf, size_t len);

