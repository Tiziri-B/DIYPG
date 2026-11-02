#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "codec/int2char.h"
#include "rsa/rsa_common_header.h"
#include "rsa/rsa_block.h"

 // N sup a 2^32

 static const rsaKey_t PUB_TEST = { .E = 65537ULL , .N = 4295360513ULL};
 static const rsaKey_t PRIV_TEST = { .E = 2740724753ULL , .N = 4295360513ULL};
 static int test_executes = 0 ;
 static int test_reussis = 0 ; 

 static void test_aller_retour_bloc( const char *nom, const uint8_t octets_in[4] ){
    test_executes++;
    printf("test %-30s :" , nom);


   // conversion des 4 octes en entier de 32 bit ( little endian)
    uint32_t m_debut = convert_4byte2int(octets_in);

     // 1.test de chiffrement 
    uint64_t c = 0 ;
    int err_chiffrer= chiffrer_bloc(m_debut , &PUB_TEST , &c);
    if (err_chiffrer != 0) {
        printf(" ECHEC de chiffrement( code %d)\n", err_chiffrer);
        return;
    }

    // 2.test de dechiffrement

    uint32_t m_dechiffre = 0 ;
    int err_dechiffrer = dechiffrer_bloc ( c, &PRIV_TEST , &m_dechiffre);
    if ( err_dechiffrer != 0)
      {  
        printf ("ECHEC de dechiffrement (code %d)\n" ,  err_dechiffrer);
        return ;
      }

    
    if(m_debut != m_dechiffre)
      {
       printf(" ECHEC  (m original: %u != m dechiffre: %u)\n" , m_debut, m_dechiffre);
       return ;
      }

      // 3. test inverse : de 32bits à 4 octes 

      uint8_t octets_sortantes[4] = {0};
      convertInt2uchar(m_dechiffre , octets_sortantes);

      if(memcmp(octets_in ,octets_sortantes , 4)!= 0 ){
        printf("ECHEC  \n");
        printf("  In  : %02x %02x %02x %02x\n", octets_in[0], octets_in[1], octets_in[2], octets_in[3]);
        printf("  Out : %02x %02x %02x %02x\n", octets_sortantes[0], octets_sortantes[1], octets_sortantes[2], octets_sortantes[3]);
        return;
      }

      printf("OK ( c= %lu)\n", (unsigned long)c);
    }



    int main(void) {
    printf(" Test de chiffrement et dechiffremnt par bloc ==\n\n");

    //  texte normal 
    uint8_t t1[4] = {'s', 'a', 'r', 'a'};
    test_aller_retour_bloc("texte initiale 'sara' " , t1);

    //  que des 0 
    uint8_t t2[4] = {0x00, 0x00, 0x00, 0x00};
    test_aller_retour_bloc("bloc nul (0x00000000)", t2);

    //m=1
    uint8_t t3[4] = {0x01, 0x00, 0x00, 0x00};
    test_aller_retour_bloc("bloc valeur 1", t3);

    // valeur random 
    uint8_t t4[4] = {0x06, 0x12, 0x23, 0x08};
    test_aller_retour_bloc("Octets 0x06, 0x12, 0x23, 0x08", t4);

    //  m=4294967295 < N
    uint8_t t5[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    test_aller_retour_bloc("valeur  0xFFFFFFFF", t5);

    // erreur m >= n 
    printf("Test :  %-30s : ", " erreur car M >= N");
    test_executes++;
    uint64_t c_invalide;

    
    rsaKey_t cle_trop_petite = { .E = 3, .N = 100 };
    if (chiffrer_bloc(500, &cle_trop_petite, &c_invalide) == -1) {
        printf("OK le test a detecter l errur  \n");
        test_reussis++;
    } else {
        printf("Echec  -1 \n");
    }

}


