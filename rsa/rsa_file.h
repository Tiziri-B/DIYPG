#ifndef RSA_FILE_H
#define RSA_FILE_H
#include "rsa_bytes.h"
#include <stddef.h>
#include "rsa_common_header.h"
void remplir_dernier_bloc(const unsigned char *reste, size_t n, unsigned char bloc[4]);

int chiffrer_fichier_bloc(const char *in, const char *out, const rsaKey_t *pub);
int dechiffrer_fichier_bloc(const char *in, const char *out, const rsaKey_t *priv);
#endif