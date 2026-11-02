#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include "../codec/int2char.h"

int main(void) {
    printf("test du int2char\n");

    // 1. test du littel endian : 4 octet en 32 bits 
    unsigned char bytes[4] = {0x01, 0x02, 0x03, 0x04};
    uint32_t val = convert_4byte2int(bytes);
    assert(val == 0x04030201);
    printf("ok pour convert_4byte2int : 0x%08X\n", val);

    // 2. Test inverse : convertInt2uchar
    unsigned char out[4] = {0};
    convertInt2uchar(val, out);
    assert(out[0] == 0x01 && out[1] == 0x02 && out[2] == 0x03 && out[3] == 0x04);
    printf("OK  pour convertInt2uchar  : %02X %02X %02X %02X\n", out[0], out[1], out[2], out[3]);

    // 3. valeur au hasard et tester l aller retour des 2 fcts 
    uint32_t original = 0xA1B2C4D3;
    unsigned char buffer[4];
    convertInt2uchar(original, buffer);
    uint32_t reconstruit = convert_4byte2int(buffer);
    assert(reconstruit == original);
    printf("OK pour les 2 fct  a la fois      : 0x%08X == 0x%08X\n", original, reconstruit);

    // 4. Test sur des ptrs  NULL
    assert(convert_4byte2int(NULL) == 0);
    convertInt2uchar(val, NULL);
    printf("OK pour les ptrs null\n");

    printf("\n ok pour les testes du ficiet int2char.c \n");
    return 0;
}