// lecture et ecriture de fichiers et conversion uint64 en 8 octets

#include "io_utils.h"
#include <stdio.h>
#include <stdlib.h>

// ecrit v sur 8 octets avec le poids faible en premier
void put_u64_le(uint8_t *dst, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        dst[i] = (uint8_t)((v >> (8 * i)) & 0xFF);
    }
}

// reconstruit le nombre a partir de 8 octets
uint64_t get_u64_le(const uint8_t *src){
    uint64_t v=0;
    for(int i=0;i<8;++i)
    {
        // cast avant le decalage sinon ca deborde
        v=v|((uint64_t)src[i]<< (8 * i));
    }
    return v;
}

// ecrit len octets dans path
// retourne 0 si ok et -1 sinon
int write_file(const char *path, const uint8_t *buf, size_t len) {
    if(path==NULL || (len >0 && buf==NULL))
        return -1;
    // wb pour le mode binaire sous windows
    FILE *f = fopen(path, "wb");
    if (f==NULL){return -1;}

    if (len > 0) {
        size_t ecrits = fwrite(buf, 1, len, f);
        if (ecrits != len) {
            fclose(f);
            return -1;
        }
    }
    if (fclose(f) != 0) {
        return -1;
    }
    return 0;
}

// lit tout le fichier path
// buf est alloue ici et libere par l appelant
int read_file(const char *path, uint8_t **buf, size_t *len) {
    if (path == NULL || buf == NULL || len == NULL) {
        return -1;
    }
    *buf = NULL;
    *len = 0;
    // rb pour le mode binaire sous windows
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -1;}

    // taille du fichier avec fseek et ftell
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;}
    long taille = ftell(f);
    if (taille < 0) {
        fclose(f);
        return -1;}
    rewind(f);

    // 1 octet minimum pour un fichier vide
    uint8_t *data = malloc(taille > 0 ? (size_t) taille : 1);
    if (data == NULL) {
        fclose(f);
        return -1;}
    if (taille > 0 && fread(data, 1, (size_t) taille, f) != (size_t) taille) {
        free(data);
        fclose(f);
        return -1;}

    fclose(f);
    *buf = data;
    *len = (size_t) taille;
    return 0;
}