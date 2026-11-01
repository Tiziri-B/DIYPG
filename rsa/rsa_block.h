#ifndef CHIFFRER_BLOC_H
#define CHIFFRER_BLOC_H
#include <stdint.h>
#include "rsa/rsa_common_header.h"

int chiffrer_bloc(uint32_t m , const rsaKey_t *pub , uint64_t *c );
int dechiffrer_bloc(uint64_t c , const rsaKey_t *priv , uint32_t *m);
#endif 