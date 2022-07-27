#include <stdio.h>
#include <stdint.h>

void read_frame(uint8_t uart_num, uint8_t *data);

int main(int argc, char *argv[])
{
    printf("Hello, World!\n");
    // define 64 byte array
    uint8_t array[64];
    read_frame(1, array);
    // print out contents of array
    for (int i = 0; i < 64; i++)
    {
        printf("%d\n", array[i]);
    }
    return 0;
}
// read a 64 byte frame of data from specified UART interface
void read_frame(uint8_t uart_num, uint8_t *data)
{
    uint32_t instruction;
    int resp;
    uint8_t i;
    for (i = 0; i < 64; i++)
    {
        instruction = 'A';
        data[i] = instruction;
    }
}