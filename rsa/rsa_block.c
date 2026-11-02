#include<stdio.h>
#include <stdint.h>
#include <gmp.h>
#include "rsa/rsa_common_header.h"
#include "rsa/rsa_gmp.h"

/** 
m : c le bloc d entier non signe de 32 bits
pub : ptr vers la cle publque 
c : ptr vers la variable du   resultat du chiffrement 
mpz_t : initiamiser la variale de gmp 
*/

// 1.choffrerment 
int chiffrer_bloc(uint32_t m , const rsaKey_t *pub , uint64_t *c ){

    // verifier la validite des ptrs
    if(pub == NULL || c == NULL){
        return -1;
    }

    // verifier la condition M<N 
    if((uint64_t)m >= pub->N){
        return -1;
    }

    //appliquer le gmp  dans la variable mpz_t 
    mpz_t resultat;  
    mpz_init(resultat);

     // calcul  de l expo modulaire 
    puissance_mod_n_gmp(resultat , (uint64_t)m , pub->E , pub->N);

    // restituer le resultat dans c 
   *c= (uint64_t)mpz_get_ui(resultat);

   // nettoyer la memo de gmp 

   mpz_clear(resultat);
   return 0 ;

}

// 2.dechiffrement 
int dechiffrer_bloc(uint64_t c , const rsaKey_t *priv , uint32_t *m){

    if(priv == NULL || m == NULL || priv ->N == 0 ){
        return -1;
    }

    if(c >= priv->N) {
        return -1;
    }

    mpz_t resultat;
    mpz_init(resultat);

    puissance_mod_n_gmp(resultat , c, priv->E , priv-> N );

    // stokcer le resultat dans m 
    *m = (uint32_t)mpz_get_ui(resultat);

    mpz_clear(resultat);

    return 0 ; 
}
