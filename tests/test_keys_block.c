# include <stdio.h>
# include <stdlib.h>
# include <inttypes.h>

# include "../rsa/rsa_keys.h"
#include "check.h"


int main(void) {
    srand(2026);

    const int NB_CLE =1000;
    int echec_gen=0;
    int n_petit=0;
    int n_grand=0;
    int n_different = 0;
    int check_rate=0;

    uint64_t n_min = 0;
    uint64_t n_max = 0;

    for (int i=0;i<NB_CLE;i++) {
        rsaKey_t pub,priv;
        if (generateKeysBlock(&pub,&priv)!=0) {
            echec_gen++;
            continue;
        }
        if (pub.N<=(1ULL<<32)) n_petit++;
        if (pub.N>=(1ULL<<63)) n_grand++;
        if (pub.N!=priv.N) n_different++;
        if (!keyCheckBlock(&pub,&priv)) check_rate++;
        if (n_min==0 || pub.N<n_min) n_min=pub.N;
        if (pub.N>n_max) n_max=pub.N;
    }

    printf("\n***** %d paires de cles generees *****\n",NB_CLE);
    printf("Plus peit N: %llu \nPlus grand N: %llu\n\n",(unsigned long long) n_min,(unsigned long long) n_max);
    verifier("Toutes les generations reusssissent",echec_gen==0);
    verifier("N n'est jamais trop petit",n_petit==0);
    verifier("N n'est jamais trop grand",n_grand==0);
    verifier("N public = N prive",n_different==0);
    verifier("keyCheckBlock accepte toutes les paires", check_rate==0);

    printf("\n***** test keyCheckBlock *****\n");
    rsaKey_t pub,priv;
    generateKeysBlock(&pub,&priv);
    verifier("paire correcte acceptee",keyCheckBlock(&pub,&priv)==1);
    verifier("NULL refuse",keyCheckBlock(NULL,&priv)==0 && keyCheckBlock(&pub,NULL)==0);

    rsaKey_t wrong = priv;
    wrong.E=priv.E+2;
    verifier("mauvais exposant prive refuse", keyCheckBlock(&pub,&wrong)==0);

    wrong=priv;
    wrong.N=priv.N+2;
    verifier("N different refuse", keyCheckBlock(&pub,&wrong)==0);

    // exemple de la phase 1
    rsaKey_t pub1,priv1;
    pub1.E=3;
    pub1.N=33;
    priv1.E=7;
    priv1.N=33;
    verifier("cles de la phase 1 (N petit) refusees", keyCheckBlock(&pub1,&priv1)==0);

    verifier("generateKeysBlock(NULL) refuse", generateKeysBlock(NULL,&priv)==-1 && generateKeysBlock(&pub,NULL)==-1);

    if (nbEchecs==0) printf("\nOK : generateKeysBlock et keyCheckBlock \n");

    return nbEchecs;
}