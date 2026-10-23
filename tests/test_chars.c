#include <stdio.h>
#include "rsa_chars.h"
#include <time.h>
#include <stdlib.h>
#include "rsa_keys.h"

//FILE *logfp = NULL; /* variable défini ailleurs , si erreur on doit le decommenté  */



/* tets 1  de la fonction chiffre/dechiffre char :
 sur 256 octet */
static int test_256_octets (void) {
    rsaKey_t pub  = { .E = 7,     .N = 97343 };
    rsaKey_t priv = { .E = 82903, .N = 97343 };
    int erreurs = 0;
    int echec = 0 ;

    for (int m = 0; m < 256; m++) {
        uint64_t c;  /* resultat chiffré sur 64 bits*/
        uint8_t  r;  /* resultat chiffré sur 8 bits */

        if (chiffrer_char((uint8_t)m, &pub, &c) != RSA_OK)
        echec = 1;
        else if ( dechiffrer_char(c, &priv, &r) != RSA_OK)
        echec = 1;
        else if (r != m) 
        echec = 1;
        if(echec){
            printf("ECHEC pour m = %d\n", m);
            erreurs++;
        }
    }
    if (erreurs == 0) printf("OK : les 256 octets sont retrouves\n");
    else              printf("%d erreurs\n", erreurs);
    return erreurs != 0;
}

 /* test 2 de la fonction chiffre/dechiffre 
 char : tets du e accent ( utf-_)*/
static int test_utf8(void){
    rsaKey_t pub  = { .E = 7,     .N = 97343 };
    rsaKey_t priv = { .E = 82903, .N = 97343 };
    const uint8_t texte[2] = {0xC3 , 0xA9};
    uint8_t clair[2];
    



    for ( int i = 0 ; i < 2 ; i++){
        uint64_t c;
        int echec  = 0 ;

        if (chiffrer_char((texte[i]), &pub, &c) != RSA_OK)
           echec = 1;
        else if ( dechiffrer_char(c, &priv, &clair[i]) != RSA_OK)
           echec = 1;
        else if (clair[i] != texte[i]) 
           echec = 1;
        if(echec){
            printf("ECHEC caractere UTF-8, octet %d\n", i);
            return 1;
        }
    }
     printf("OK : UTF-8, retrouve %c%c\n", clair[0], clair[1]);
    return 0;
}


    /* test 3 de la fonction chiffre/dechiffre char :
     tets sur 500 paires de clefs generes avec 256 octets  */

     static int test_boucle (void){
        int erreurs = 0 ;
        int ignores =  0 ; 
        int echecs_gen = 0 ;
        int testees =0 ; 
        

        for ( int i = 0 ; i < 500 ; i ++){
            rsaKey_t pub, priv ;
             if (generateKeys(&pub, &priv) != 0) 
             { 
                echecs_gen++;
                 continue; 
             }
             if (pub.N <= 255) 
             {
                 ignores++;
                  continue;
             }   
             testees++;

            for (int m = 0; m < 256; m++) {
              uint64_t c;
              uint8_t  r;
              int echec = 0 ;

              if (chiffrer_char((uint8_t)m, &pub, &c) != RSA_OK)
                echec = 1;
              else if ( dechiffrer_char(c, &priv, &r) != RSA_OK)
                echec = 1;
              else if (r != m) 
                echec = 1;
              if(echec){
                 printf("ECHEC clef %d (E=%lu, N=%lu), octet %d\n", i,
                       (unsigned long)pub.E, (unsigned long)pub.N, m);
            erreurs++;
        }
    }
}

    printf("Boucle : %d clefs testees, %d ignorees (N <= 255), %d echecs de generation, %d erreurs\n",
           testees, ignores, echecs_gen, erreurs);
    if (testees == 0) {
        printf("ECHEC : aucune clef utilisable\n");
        return 1;
    }
    return erreurs;
        }
    


/* main */

int main(void) {
    srand((unsigned)time(NULL));
    int erreurs = test_256_octets() + test_utf8() + test_boucle();

    if (erreurs == 0) printf("OK : test_chars\n");
    else              printf("ECHEC : test_chars (%d erreurs)\n", erreurs);
    return erreurs != 0;
}