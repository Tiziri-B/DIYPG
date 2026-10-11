# include <stdio.h>
# include "../rsa/rsa_keys.h"
# include "../rsa/rsa_tools.h"

int main() {
    int nbCles = 3000;

    srand(2026);
    logfp= tmpfile();

    uint64_t limite = 1ULL << 32;  // 2 puissance 32

    int grande=0; // cle dont N >= limite
    int echecGrande=0; // grande + ne marche pas
    int echecPetite=0; // cle dont N < limite et ne marche pas

    uint64_t nMax=0 ;//plus grand N rencontré

    for (int i=0; i<nbCles; i++) {
        rsaKey_t pub,priv;
        genKeysRabin(&pub,&priv,MAX_PRIME);

        nMax=MAXI(pub.N,nMax);

        int valide = keyCheck(&pub,&priv);

        if (pub.N >limite) {
            grande++;
            if (!valide) {
                echecGrande++;
            }
        } else if (!valide) {
            echecPetite++;
        }
    }

    printf("\n ***** Résultats test MAXPRIME ***** \n");
    printf("MAX_PRIME : %d \n",MAX_PRIME);
    printf("Nombre de clés téstées : %d \n",nbCles);
    printf("Clés grandes (avec N >= 2^32) : %d \n",grande);
    printf("Clés grandes qui échouent : %d \n",echecGrande);
    printf("Autres clés qui échouent : %d \n",echecPetite);
    printf("Plus grand N obtenu : %llu \n",(unsigned long long) nMax);
    printf("*******************************************\n");
}