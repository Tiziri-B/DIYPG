# include <stdio.h>
# include <stdlib.h>
# include <inttypes.h>

# include "../rsa/rsa_tools.h"
# include "../rsa/rsa_keys.h"

int nbEchecs = 0;

void verifier(int cnd, const char * msg) {
    if (cnd) {
        printf ("OK : %s\n",msg);
    } else {
        printf("ECHEC : %s\n",msg);
        nbEchecs++;
    }
}

int main(void) {

    srand(2026);

    // test: sujet
    printf("***** Exemple du sujet *****\n");
    printf("La clé publique d'Alice est (n,e)=(33,3) \n");
    printf("Sa clé privée est (n,d)=(33,7) \n");
    verifier(puissance_mod_n(4,3,33)==31, "le chiffrement de 4 donne 31");
    verifier(puissance_mod_n(31,7,33)==4, "le déchiffrement de 31 donne 4");

    // test: Affichage en hexa
    printf("\n ***** Affichage en hexadécimal ***** \n");
    rsaKey_t k;
    k.E=3;
    k.N=33;
    printf("attendu : \n");
    printf("E = 0x3 \n");
    printf("N = 0x21 \n");
    printf("obtenu : \n");
    printKey(&k,stdout);
    printf("\n");

    // test: Générer et afficher une paire
    printf("\n ***** une paire de clés générée ***** \n");
    keys_set_log(stdout);
    rsaKey_t pub,priv;
    if (generateKeys(&pub,&priv)==0) {
        printKeyPair(&pub,&priv,stdout);
    } else {
        printf (" ECHEC : génération d'une paire de clés \n");
        nbEchecs++;
    }

    // test: generation 100 clés
    printf("\n ***** Générer 100 paires de clés ***** \n");
    int erreurGen = 0;
    for (int i=0; i<100 ; i++) {
        rsaKey_t pub, priv ;
        if (generateKeys(&pub,&priv)!=0) {
            erreurGen++;
        }
        if (pub.N <= 255) {
            erreurGen++;
        }
    }
    verifier(erreurGen==0,"les 100 paires de clés sont correctes");

    // Bilan
    printf("\n");
    if (nbEchecs==0) printf("Tout est OK \n");
    else printf("%d vérification(s) échouée(s) \n",nbEchecs);

    return nbEchecs;

}
