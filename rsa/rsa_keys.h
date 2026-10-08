#ifndef RSA_KEYS_H
#define RSA_KEYS_H
#include <stdio.h>
#include "rsa_common_header.h"

/* Affiche E et N en hexadecimal. */
void key_print_hex(const rsaKey_t *k, FILE *out);

/* Genere une paire de clefs. Refuse (ou retire) un N <= 255. 0 = succes. */
int keys_generate(keyPair_t *kp);
#endif
