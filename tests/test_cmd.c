#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "cmd_keys.h"

static int erreurs =0 ; 
#define VERIFICATION(cond , msg) do {if (!(cond)) {printf(" echec : %s\n" , msg); erreurs++ ;}}while (0)
int main ( void){
    srand((unsigned) time(NULL));
    KeyRing kr; 
    keyring_init(&kr);

    char *newkey[] = {"newkeys" , "nadine" , "crypt"};
    char *bad_type[] = {"newkeys" , "maria" , "xxx"};
    char  *listk[]= {"newkeys"};
    char *listk2[]= {"newkeys" , "yyy"};
    char *sh[]= {"show" , "nadine"};
    char *shpriv[] ={"show" , "nadine" ,"priv"}; 
    char *shautre[] ={"show" , "nadine" ,"autre"};
    char *remove[] ={"rmkeys" , "nadine"};  

    VERIFICATION(cmd_newkeys(&kr, 3, newkey)  == KR_OK,"newkeys nadine");
    VERIFICATION(cmd_newkeys(&kr, 3, newkey)  == KR_ERR_EXISTS, "pas de doublon");
    VERIFICATION(cmd_newkeys(&kr, 3, bad_type) == KR_ERR_TYPAGE,"type pas valide");
    VERIFICATION(cmd_newkeys(&kr, 2, newkey)  == CMD_ERR_USAGE, "argm manquant ");
    VERIFICATION(cmd_listkeys(&kr, 1, listk) == CMD_OK,"listkeys");
    VERIFICATION(cmd_listkeys(&kr, 2, listk2)== KR_ERR_NOTFOUND, "listkeys inconnu");
    VERIFICATION(cmd_show(&kr, 2, sh)  == CMD_OK,  "show de la clef pub par defaut ");
    VERIFICATION(cmd_show(&kr, 3, shpriv) == CMD_OK,  "show de la clef priv");
    VERIFICATION(cmd_show(&kr, 3, shautre) == CMD_ERR_USAGE, "inconnu pour le  show ");
    VERIFICATION(cmd_rmkeys(&kr, 2, remove) == CMD_OK, "rmkeys");
    VERIFICATION(cmd_rmkeys(&kr, 2, remove) == KR_ERR_NOTFOUND, "plus rien a supp");

    keyring_free(&kr);
    if (erreurs == 0) printf("Ok les tests de cmd_keys marchent \n");
    else              printf("echec : detection de %d  erreurs sur les cmd\n", erreurs);
    return erreurs != 0;

}
    

    