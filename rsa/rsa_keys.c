# include <stdio.h>
# include "rsa_keys.h"

void afficherCle(rsaKey_t cle){
    printf("E = 0x%" PRIx64 "\n",cle.E);
    printf("N = 0x%" PRIx64 "\n, cle.N");
}

void afficherPaireCles(keyPair_t paire) {
    printf("***** Cle publique *****\n");
    afficherCle(paire.pubKey);

    printf("***** Cle privée *****\n");
    afficherCle(paire.privKey);
}

void genererPaireCles(keyPair_t*paire,uint64_t max_prime) {
    genKeysRabin(&paire->pubKey,&paire->privKey,max_prime);
}
