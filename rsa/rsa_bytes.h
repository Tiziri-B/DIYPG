#ifndef RSA_BYTES_H
#define RSA_BYTES_H

#include <stdint.h>
#include <stddef.h>
#include "rsa_common_header.h"
#include "rsa_chars.h"

#ifndef RSA_ERR_MEM
#define RSA_ERR_MEM (-4)
#endif
#ifndef RSA_ERR_IO
#define RSA_ERR_IO (-100)
#endif

int chiffrer_octets(const uint8_t *in, size_t len, const rsaKey_t *pub, uint8_t **out, size_t *out_len);
int dechiffrer_octets(const uint8_t *in, size_t len, const rsaKey_t *priv, uint8_t **out, size_t *out_len);
int chiffrer_fichier(const char *in, const char *out, const rsaKey_t *pub);
int dechiffrer_fichier(const char *in, const char *out, const rsaKey_t *priv);

#endif