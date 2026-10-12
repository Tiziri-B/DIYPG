#ifndef RSA_BYTES_H
#define RSA_BYTES_H
#include <stddef.h>
#include <stdint.h>
#include "rsa_common_header.h"

/* Chaque octet donne un chiffre ecrit sur 8 octets : out_len = 8 * len.
   L'appelant fait free(*out). */
int chiffrer_octets  (const uint8_t *in, size_t len, const rsaKey_t *pub,
                      uint8_t **out, size_t *out_len);

/* len doit etre un multiple de 8. */
int dechiffrer_octets(const uint8_t *in, size_t len, const rsaKey_t *priv,
                      uint8_t **out, size_t *out_len);

int chiffrer_fichier  (const char *fichier_in, const char *fichier_out, const rsaKey_t *pub);
int dechiffrer_fichier(const char *fichier_in, const char *fichier_out, const rsaKey_t *priv);
#endif
