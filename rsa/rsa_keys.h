#ifndef RSA_KEYS_H
#define RSA_KEYS_H

#include "rsa_common_header.h"

/* Affiche une cle RSA en hexadecimal */
void printKey(const rsaKey_t *k, FILE *out);


/* Affiche la cle publique et la cle privee */
void printKeyPair(const rsaKey_t *pub, const rsaKey_t *priv, FILE *out);

/* pour le moment je ne sait pas si c necessaire */
void keys_set_log(FILE *f);


// verifie une cle peut dé/chiffrer 
int keyCheck (const rsaKey_t *pub, const rsaKey_t *priv);


/* Génération des clés */
// 0 si paire valide sinon -1
int generateKeys(rsaKey_t *pub, rsaKey_t *priv);


#endif