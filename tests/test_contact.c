#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "contacts.h"
#include "storage.h"
#include "check.h"

int main(void) {
    KeyRing kr;
    keyring_init(&kr);

    verifier("ajout contact réussit ",contact_add(&kr, "jeannot", "Dupuis", "Jean", "Voisin du dessus") == KR_OK);
    verifier("ajaout contact existant",contact_add(&kr, "jeannot", "Autre", "Jean", "") == KR_ERR_EXISTS);
    verifier("contact existant trouvé",contact_find(&kr, "jeannot") != NULL);
    verifier("contact existant trouvé",contact_find_name(&kr, "Dupuis") != NULL);
    verifier("contact modifié ",contact_modify(&kr, "jeannot", "Dupuis", "Jean-Pierre", "Voisin") == KR_OK);
    verifier("contact modifié : le prenom a bien changé",strcmp(contact_find(&kr, "jeannot")->prenom, "Jean-Pierre") == 0);

    rsaKey_t pub = {65537, 4294967311ULL};
    verifier("ajout d'une cle au contact",contact_addkey(&kr, "jeannot", "boulot", KEY_TYPE_CRYPT, &pub) == KR_OK);
    verifier("ajout de la meme cle au contact (doublon)",contact_addkey(&kr, "jeannot", "boulot", KEY_TYPE_CRYPT, &pub) == KR_ERR_EXISTS);
    verifier("supression d'une cle d'un contact",contact_removekey(&kr, "jeannot", "boulot") == KR_OK);
    verifier("nombre de cles du contact change apres la supression",contact_find(&kr, "jeannot")->nb_cles == 0);
    verifier("ajout d'une cle au contact",contact_addkey(&kr, "jeannot", "perso", KEY_TYPE_CRYPT, &pub) == KR_OK);

    verifier("save reussit",storage_save(&kr, "build/contacts_test.dat") == 0);
    KeyRing charge;
    keyring_init(&charge);

    verifier("load reussit",storage_load(&charge, "build/contacts_test.dat") == 0);
    Contact *c = contact_find(&charge, "jeannot");
    verifier("load contact reussit et inchage",c != NULL && strcmp(c->nom, "Dupuis") == 0 && c->nb_cles == 1);
    verifier("load cle contact reussit",c->cles[0].pubKey.N == pub.N);
    verifier("supression du contact reussit",contact_remove(&charge, "jeannot") == KR_OK);
    verifier("contact supprimé n'existe plus",contact_find(&charge, "jeannot") == NULL);

    // identifiant avec '|' refuse (sinon la sauvegarde devient illisible)
    verifier("identifiant avec | refuse", contact_add(&kr, "a|b", "Nom", "Prenom", "") == KR_ERR_BADID);

    // commentaire vide : doit survivre a save puis load
    verifier("ajout contact sans commentaire", contact_add(&kr, "lea", "Martin", "Lea", "") == KR_OK);
    verifier("save avec commentaire vide", storage_save(&kr, "build/contacts_test.dat") == 0);
    KeyRing vide;
    keyring_init(&vide);
    verifier("load avec commentaire vide", storage_load(&vide, "build/contacts_test.dat") == 0);
    verifier("commentaire vide conserve", contact_find(&vide, "lea") != NULL && contact_find(&vide, "lea")->commentaire[0] == '\0');
    keyring_free(&vide);

    // contact_findkey et savepub sur une clef de contact
    verifier("contact_findkey trouve jeannot/perso", contact_findkey(&kr, "jeannot/perso") != NULL);
    verifier("contact_findkey : clef inconnue", contact_findkey(&kr, "jeannot/rien") == NULL);
    verifier("contact_findkey : contact inconnu", contact_findkey(&kr, "personne/perso") == NULL);
    verifier("savepub d'une clef de contact", storage_savepub(&kr, "jeannot/perso", "build/contact_pub.txt") == 0);
    verifier("savepub d'une clef de contact inconnue", storage_savepub(&kr, "jeannot/rien", "build/contact_pub.txt") == -1);
    remove("build/contact_pub.txt");

    // ligne CONTACTKEY abimee : le load doit echouer
    FILE *f = fopen("build/contacts_test.dat", "w");
    fprintf(f, "CONTACT|bob|B|Bob|\nCONTACTKEY|bob|k|crypt|abc|12\n");
    fclose(f);
    KeyRing abime;
    keyring_init(&abime);
    verifier("load refuse une CONTACTKEY abimee", storage_load(&abime, "build/contacts_test.dat") == -1);
    keyring_free(&abime);

    keyring_free(&kr);
    keyring_free(&charge);
    remove("build/contacts_test.dat");
    return nbEchecs;
}
