#ifndef RSA_KEYS_H
#define RSA_KEYS_H
<<<<<<< HEAD
#include <stdio.h>
#include "rsa_common_header.h"

/* Affiche E et N en hexadecimal. */
void key_print_hex(const rsaKey_t *k, FILE *out);

/* Genere une paire de clefs. Refuse (ou retire) un N <= 255. 0 = succes. */
int keys_generate(keyPair_t *kp);
#endif
=======

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


#endif
>>>>>>> a506d7723e6402f98b622e307f817e33476b1e20
