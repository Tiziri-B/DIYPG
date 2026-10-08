#ifndef RSA_KEYIO_H
#define RSA_KEYIO_H
#include "rsa_common_header.h"

/* Sauvegarde / charge une paire de clefs (fichier texte, valeurs en hexadecimal).
   ATTENTION : le fichier contient la clef privee. 0 = succes, negatif = erreur. */
int key_save(const char *path, const keyPair_t *kp);
int key_load(const char *path, keyPair_t *kp);
#endif
