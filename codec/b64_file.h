#ifndef B64_FILE_H
#define B64_FILE_H
#include <stddef.h>
#include <stdint.h>

/* A ne definir que si other_base64.c ne les fournit pas deja (eviter les doublons). */
int b64_encode(const uint8_t *in, size_t len, char **out);
int b64_decode(const char *in, uint8_t **out, size_t *len);

int fichier_vers_b64(const char *fichier_in, const char *fichier_out);
int b64_vers_fichier(const char *fichier_in, const char *fichier_out);
#endif
