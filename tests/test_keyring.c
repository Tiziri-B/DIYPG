#include <stdio.h>
#include <assert.h>
#include "keyring.h"

int main(){
    printf(" tests sur l annuaire (keyring) \n");
    KeyRing kr;

    // test 1 : initialisation 
    assert(keyring_init(&kr) == KR_OK);
    printf(" OK :  l initialisation de l annuaire fonctionne \n");

    // test 2 : ajout d une 1ere clef crypt 
    int resultat1 = keyring_new(&kr , "thanina" , "crypt");
    if(resultat1 != KR_OK){
        printf("erreur lors de lajout de thanina : %s\n",keyring_erreur(resultat1));
    }
    assert(resultat1 == KR_OK);
    printf("OK ajout de la clé 'thanina' (crypt) \n");


    // test 3  : ajout d une cle de signature
    int resultat2 = keyring_new(&kr , "cylia" , "sign");
    assert(resultat2 == KR_OK);
    printf("OK ajout de la clé 'cylia' (sign) \n");

    // test 4 : ajouter un doublon 
    int doublon  = keyring_new(&kr , "thanina" , "crypt");
    assert(doublon == KR_ERR_EXISTS);
        printf(" OK  : le teste detecte qu il y a des doublons (thanina) \n");

  // test 5 : id invalide
    int bad_id1  = keyring_new(&kr , "bad id" , "crypt");
    assert(bad_id1 == KR_ERR_BADID);

    int bad_id2  = keyring_new(&kr , "bad/id" , "crypt");
    assert(bad_id2 == KR_ERR_BADID);
    printf("OK rejet des id invalides.\n");


    //test 6 :  type invalide 
    int bad_type  = keyring_new(&kr , "maria" , "unknow");
    assert(bad_type == KR_ERR_TYPAGE);
    printf("OK rejet des type invalides.\n");


    // test 7 : recherhce de cles 
    KeyEntry *found_thanina = keyring_find(&kr, "thanina");
    assert(found_thanina != NULL);
    assert(strcmp(found_thanina->id, "thanina") == 0);
    printf("ok recherche de thanina fonctionne\n");

    KeyEntry *found_autre = keyring_find(&kr, "autre");
    assert(found_autre == NULL);
    printf("ok recherche de 'autre' correct.\n");



    // test 8 : affichage ( fct list) 
    printf("affichage \n");
    keyring_list(&kr ,NULL);
    

    // test 9 : suppression 
    int supprimer = keyring_remove(&kr, "cylia");
    assert(supprimer == KR_OK);
    assert(keyring_find(&kr , "cylia") == NULL);
    printf("ok suppression resussie de 'cylia'.\n");

    // test 10 : free de la mémo 
    keyring_free(&kr);
    printf("ok la memoire est liberee.\n");
    return 0 ;
}