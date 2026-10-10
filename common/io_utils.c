#include "io_utils.h"
#include <stdio.h>
#include <stdlib.h>
void put_u64_le(uint8_t *dst, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        dst[i] = (uint8_t)((v >> (8 * i)) & 0xFF);
    }
}

uint64_t get_u64_le(const uint8_t *src){
    uint64_t v=0;
    for(int i=0;i<8;++i)
    {
        v=v|((uint64_t)src[i]<< (8 * i));
    }
    return v;
}
int write_file(const char *path, const uint8_t *buf, size_t len) {
    // 1. verifier path ; verifier buf si len > 0
    if(path==NULL || (len >0 && buf==NULL))
        return -1;

    // 2. ouvrir le fichier en ecriture binaire
    FILE *f = fopen(path, "wb");
    if (f==NULL){return -1;}

    // 3. ecrire len octets
    if (len > 0) {
        size_t ecrits = fwrite(buf, 1, len, f);
        if (ecrits != len) {
            fclose(f);
            return -1;
        }
    }
    // 4. fermer et verifier que tout s'est bien passe
    // 5. retourner 0 (ou -1 a chaque echec)
    if (fclose(f) != 0) {
        return -1;
    }
    return 0;
}
int read_file(const char *path, uint8_t **buf, size_t *len) {
    if (path == NULL || buf == NULL || len == NULL) {
        return -1;
    }
    *buf = NULL;
    *len = 0;

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long taille = ftell(f);
    if (taille < 0) {
        fclose(f);
        return -1;
    }
    rewind(f);

    uint8_t *data = malloc(taille > 0 ? (size_t) taille : 1);
    if (data == NULL) {
        fclose(f);
        return -1;
    }

    if (taille > 0 && fread(data, 1, (size_t) taille, f) != (size_t) taille) {
        free(data);
        fclose(f);
        return -1;
    }

    fclose(f);
    *buf = data;
    *len = (size_t) taille;
    return 0;
}