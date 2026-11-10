#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "cmd_keys.h"
#include "contacts.h"

static int erreur(const char *cmd , int code)
{
    fprintf(stderr, "%s : %s\n" , cmd , keyring_erreur(code));
    return code;
}

static int usage(const char*texte){
    fprintf(stderr , "usage : %s\n", texte);
    return CMD_ERR_USAGE;
}

static void affichage_cle(const char *titre , const rsaKey_t *k){
    printf("%-16s E = 0x%" PRIx64 "N = 0x%" PRIx64 "\n"  ,titre  ,k->E , k->N);
}

// 1. commande pour créer une nvl clef
int cmd_newkeys(KeyRing *kr , int argc ,char **argv){
    if(kr == NULL || argv == NULL ) return KR_ERR_PTR;
    if(argc !=3) return usage("newkeys  <keyid> <crypt|sign>");

    // ranger le resultat de l apppel de keyring dans r 
    int r = keyring_new (kr ,argv[1] ,argv[2]);
    if(r != KR_OK) return erreur("newkeys", r);

    printf("clef '%s' (%s) a ete creer\n", argv[1], argv[2]);
    return CMD_OK;
}

// 2. commande pour lister les clefs de l annuaire 
int cmd_listkeys(KeyRing *kr , int argc ,char **argv){
    if(kr == NULL || argv == NULL ) return KR_ERR_PTR;
    if(argc !=1 && argc != 2) return usage("listkeys [<keyid>]");

    // afficher rien si il ne reconnait pas l id de la clef
    if( argc==2 && keyring_find(kr, argv[1]) == NULL) return erreur("listkeys" , KR_ERR_NOTFOUND);

    keyring_list(kr, (argc==2) ? argv[1] : NULL);
    return CMD_OK;
}


//3. commande pour supprimer une clef à partir de l id 
int cmd_rmkeys(KeyRing *kr , int argc ,char **argv){
    if(kr == NULL || argv == NULL ) return KR_ERR_PTR;
    if(argc != 2) return usage("rmkeys <keyid> ou <idcontact>/<keyid>");

    // cle du contact
    char *separateur = strchr(argv[1], '/');
    if (separateur != NULL) {
        *separateur = '\0';
        int r = contact_removekey(kr, argv[1], separateur + 1);
        if(r != KR_OK) return erreur("rmkeys", r);
        printf("cle '%s' supprimee du contact '%s'\n", separateur + 1, argv[1]);
        return CMD_OK;
    }

    int r = keyring_remove (kr ,argv[1]);
    if(r != KR_OK) return erreur("rmkeys", r);

    printf("clef '%s'  a ete supprimer \n", argv[1]);
    return CMD_OK;
}

// 4. commande pour  recupérer la cle priv ou pub 
int cmd_show(KeyRing *kr , int argc ,char **argv){
    if(kr == NULL || argv == NULL ) return KR_ERR_PTR;
    if(argc < 2 || argc > 4) return usage("show <keyid> [pub] [priv]");

    int recup_pub = 0 , recup_priv = 0 ;
    for( int i = 2 ; i < argc ;i++){
        if(strcmp(argv[i], "pub") == 0 ) recup_pub =1;
        else if(strcmp(argv[i] , "priv") == 0 ) recup_priv = 1; 
        else return usage ("show <keyrid> [pub] [priv]");

    }
    // par defult on affiche la clé pub seulemnts 
    if( !recup_priv && !recup_pub) recup_pub =1 ; 

    // partie contact
    char *slash = strchr(argv[1], '/');
    if (slash != NULL) {
        if (recup_priv) return usage("show <idcontact>/<keyid> [pub]");
        *slash = '\0';
        Contact *c = contact_find(kr, argv[1]);
        if (c == NULL) return erreur("show", KR_ERR_NOTFOUND);
        for (int i = 0; i < c->nb_cles; i++) {
            if (strcmp(c->cles[i].id, slash + 1) == 0) {
                printf("%s/%s (%s)\n", c->id, c->cles[i].id, c->cles[i].type);
                if (recup_pub) affichage_cle("cle publique : ", &c->cles[i].pubKey);
                return CMD_OK;
            }
        }
        return erreur("show", KR_ERR_NOTFOUND);
    }

    // mettre le resultat dans e 
    KeyEntry *e  =keyring_find(kr, argv[1]);
    if( e== NULL ) return erreur ("show" , KR_ERR_NOTFOUND);
    
     printf("%s (%s)\n", e->id , e->type);
     if(recup_pub)affichage_cle("la clef publique est : " , &e->keys.pubKey);
     if(recup_priv)affichage_cle("la clef privee est : " , &e->keys.privKey);
     return CMD_OK;
}
