#ifndef RSA_KEYS_H
#define RSA_KEYS_H

#include "rsa_common_header.h"

/* Affiche une cle RSA en hexadecimal */
void afficherCle(const char *nom, const rsaKey_t *cle);

/* Affiche la cle publique et la cle privee */
void afficherPaireCles(const keyPair_t *paire);

/* fournis */
void genKeysRabin(rsaKey_t *pubKey,rsaKey_t *privKey,uint64_t max_prime);

/* Génération des clés */
void genererPaireCles(keyPair_t*paire,uint64_t max_prime);
#endif