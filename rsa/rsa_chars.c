/* ce code est la fonction de chiffrement  et de dechiffrement caractere par caractere */

#include "rsa_chars.h"

/* fonction fourni : depuis rsa_tools.c*/
uint64_t puissance_mod_n(uint64_t a , uint64_t e, uint64_t n) ;



int chiffrer_char( uint8_t m , const rsaKey_t * pub, uint64_t *c){  
      /* m= la valeur a chiffrer --- rsaKey_t : c la stucture de la cle E et N ----c = la valeur chiffree*/
  if( pub == NULL || c== NULL) return RSA_ERR_ARG;
  if(pub->N <= 255) return RSA_ERR_SMALL_N;
  *c = puissance_mod_n((uint64_t)m , pub->E, pub->N);
  return RSA_OK;
}


int dechiffrer_char(uint64_t c, const rsaKey_t *priv, uint8_t *m) {
    if (priv == NULL || m == NULL) return RSA_ERR_ARG;
    if (priv->N <= 255) return RSA_ERR_SMALL_N;
    if (c >= priv->N) return RSA_ERR_RANGE;      
    uint64_t r = puissance_mod_n(c, priv->E, priv->N);
    if (r > 255) return RSA_ERR_RANGE;           
    *m = (uint8_t)r;
    return RSA_OK;
}
