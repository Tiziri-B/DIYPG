#include "int2char.h"
#include <stddef.h>

//fonction1 : former un bloc de 32 bits pour chaque 4 octets d'un fichier ou d un message 

uint32_t convert_4byte2int(const unsigned char *b){
if(b == NULL) return 0;
uint32_t resultat = 0 ;

// expl : (((uint32_t)b[1]) << 8) vzut dire faire :
//  un decalage vers la gauche du bits 8 à 15
for ( int i =0 ; i <4  ;i ++)
  {
    resultat |= ((uint32_t)b[i]) << ( 8 * i);
  }
  return resultat;
}



void convertInt2uchar(uint32_t nb , unsigned char* tab4bytes){
  if (tab4bytes == NULL ) return ;
tab4bytes[0] = ( unsigned char )(nb & 0xFF);
tab4bytes[1] = ( unsigned char )((nb >> 8) & 0xFF);
tab4bytes[2] = ( unsigned char )((nb >> 16) & 0xFF);
tab4bytes[3] = ( unsigned char )((nb >> 24) & 0xFF);
}
