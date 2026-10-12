# include <stdio.h>
# include <inttypes.h> // afficher et manipuler types uint64_t
# include "rsa_keys.h"
# include "rsa_tools.h" 


FILE *logfp = NULL;

void keys_set_log(FILE *f){
    logfp= f;
}

void printKey(const rsaKey_t *k, FILE *out) {
    if (k== NULL || out == NULL) return;
    fprintf(out,"E = 0x%" PRIx64 "\n",k->E);
    fprintf(out,"N = 0x%" PRIx64 "\n", k->N);
    // PRIx64 : permet d’afficher un entier non signé de 64 bits en hexa
}

void printKeyPair(const rsaKey_t *pub, const rsaKey_t *priv, FILE *out){
    fprintf(out,"***** Clé publique *****\n");
    printKey(pub,out);

    fprintf(out,"\n***** Clé privée *****\n");
    printKey(priv,out);
    fprintf(out,"\n");
}


int keyCheck (const rsaKey_t *pub, const rsaKey_t *priv){
    if (pub==NULL || priv==NULL) return 0;
    if (pub->N!=priv->N || pub->N <= 255) return 0;

    for (uint64_t m=0; m<256; m++) {
        uint64_t c=puissance_mod_n(m,pub->E,pub->N); //chiffrement
        if (puissance_mod_n(c,priv->E,priv->N)!=m) return 0; // dechiffrement
    }
    return 1;
}



int generateKeys(rsaKey_t *pub, rsaKey_t *priv) {
    if (pub==NULL || priv==NULL) return -1;
    if (logfp==NULL) logfp=tmpfile(); // necessaire pour genKeysRabin
    if (logfp==NULL) return -1;

    for (int essai=0 ; essai < KEYS_TRIES; essai++) {
        genKeysRabin(pub,priv,MAX_PRIME);
        if (keyCheck(pub,priv)) return 0;
    }

    return -1;
}
