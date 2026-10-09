# include <stdio.h>
# include <inttypes.h> // afficher et manipuler types uint64_t
# include "rsa_keys.h"

void printKey(rsaKey_t* k){
    if (k== NULL) return;
    printf("E = 0x%" PRIx64 "\n",k.E);
    printf("N = 0x%" PRIx64 "\n", k.N);
}

void printKeyPair(keyPair_t paire) {
    printf("***** Cle publique *****\n");
    printKey(paire.pubKey);

    printf("\n***** Cle privée *****\n");
    printKey(paire.privKey);
    printf("\n");
}

void generateKeys(keyPair_t*paire,uint64_t max_prime) {
    genKeysRabin(&paire->pubKey,&paire->privKey,max_prime);
}
