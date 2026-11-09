#ifndef RSA_KEYS_H
#define RSA_KEYS_H

#include <stdio.h>
#include "rsa_common_header.h"

//nb max d'essais avant d'abandonner
#define KEYS_TRIES 50

/* Affiche une cle RSA en hexadecimal */
void printKey(const rsaKey_t *k, FILE *out);

/* Affiche la cle publique et la cle privee */
void printKeyPair(const rsaKey_t *pub, const rsaKey_t *priv, FILE *out);

/* pour genKeysRabin / ou voir les etapes de generation */
void keys_set_log(FILE *f);

// verifie une paire de cles peut dé/chiffrer et compatible
int keyCheck (const rsaKey_t *pub, const rsaKey_t *priv);

/* Génération des clés */
// 0 si paire valide est générée sinon -1 (echec de generation)
int generateKeys(rsaKey_t *pub, rsaKey_t *priv);


/* ***** PHASE 2 ***** */

// verification pour des blocs de 4 octets
// renvoie 1 si ok, 0 sinon
int keyCheckBlock(const rsaKey_t *pub, const rsaKey_t *priv);

// generation des clés (N >2^32)
// 0 si paire valide est générée sinon -1 
int generateKeysBlock(rsaKey_t *pub, rsaKey_t *priv);

#endif