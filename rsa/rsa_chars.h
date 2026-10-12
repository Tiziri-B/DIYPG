#ifndef RSA_CHARS_H
#define RSA_CHARS_H
#include <stdint.h>
#include "rsa_common_header.h"

#define RSA_OK           0
#define RSA_ERR_ARG     -1
#define RSA_ERR_SMALL_N -2
#define RSA_ERR_RANGE   -3

/* Chiffre un octet : *c = m^E mod N */
int chiffrer_char(uint8_t m, const rsaKey_t *pub, uint64_t *c);

/* Dechiffre : *m = c^E mod N. Erreur si le resultat depasse 255. */
int dechiffrer_char(uint64_t c, const rsaKey_t *priv, uint8_t *m);
#endif
