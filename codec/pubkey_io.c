#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "pubkey_io.h"
#include "b64_file.h"
#include "io_utils.h"

int pubkey_export(const char *path,const rsaKey_t *pub) {
    if (path==NULL||pub==NULL) return -1;

    uint8_t octets[16];
    put_u64_le(octets,pub->E);
    put_u64_le(octets+8,pub->N);

    char *texte=NULL;
    if (b64_encode(octets,16,&texte)!=0) return -1;

    FILE *f= fopen(path,"w");
    if (f==NULL) {
        fprintf(stderr,"pubkey_export : impossible d'écrire dans %s\n",path);
        free(texte);
        return -1;
    }
    fprintf(f,"%s\n",texte);
    fclose(f);
    free(texte);
    return 0;
}


int pubkey_import(const char *path, rsaKey_t *pub){
    if (path==NULL||pub==NULL) return -1;

    uint8_t *buff=NULL;
    size_t taille=0;
    if (read_file(path,&buff,&taille)!=0) {
        fprintf(stderr,"pubkey_import: impossible de lire %s\n",path);
        return -1;
    }

    char *texte=malloc(taille+1);
    if(texte==NULL) {
        free(buff);
        return -1;
    }
    size_t n=0;
    for (size_t i=0;i<taille;i++) {
        if (buff[i]!='\n' && buff[i]!='\r' && buff[i]!='\t' && buff[i]!=' ' ) {
            texte[n]=(char) buff[i];
            n++;
        }
    }
    texte[n]='\0';
    free(buff);

    uint8_t *octets=NULL;
    size_t nb=0;
    int decode=b64_decode(texte,&octets,&nb);
    free(texte);
    if (decode!=0 || nb!=16) {
        fprintf(stderr,"pubkey_import : %s ne contient pas une clé valide\n",path);
        free(octets);
        return -1;
    }

    rsaKey_t cleLue;
    cleLue.E=get_u64_le(octets);
    cleLue.N=get_u64_le(octets+8);
    free(octets);

    if (cleLue.N <=(1ULL<<32)-1) {
        fprintf (stderr,"clé inutilisable");
        return -1;
    }

    *pub=cleLue;
    return 0;
}