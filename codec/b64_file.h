# ifndef B64_FILE_H
#define B64_FILE_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// fournis 
void base64_cleanup(void);
char *base64_encode(const unsigned char *data,size_t input_length,size_t *output_length);
unsigned char *base64_decode(const char *data,size_t input_length,size_t *output_length);
            
// fonctions ajoutées

// lecture fichier bin (in) -> ecriture b64 dans fichier (out)
// 0 si tout va bien, -1 en cas d'erreur 
int fichier_vers_b64(const char *in, const char *out);

// lecture fichier B64 (in) -> ecriture octets dans fichier (out)
// 0 si tout va bien, -1 en cas d'erreur 
int b64_vers_fichier(const char *in, const char *out);

#endif