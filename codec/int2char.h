#ifndef INT2CHAR_H
#define INT2CHAR_H // ppur ne pas avoir des doubles declaration et faire crasher le compilateur 
#include <stdint.h>

typedef unsigned char uchar;
typedef unsigned int uint;

uint32_t convert_4byte2int(const unsigned char *b);
void convertInt2uchar(uint32_t nb , unsigned char* tab4bytes);

#endif