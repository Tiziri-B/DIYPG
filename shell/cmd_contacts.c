#include <stdio.h>
#include <string.h>
#include "cmd_contacts.h"
#include "contacts.h"
#include "pubkey_io.h"
#include "affichage.h"

static int usage(const char *texte) {
    aff_erreur("usage : %s\n", texte);
    return CMD_ERR_USAGE;
}

static int erreur_contact(const char *cmd, int r) {
    aff_erreur("%s : %s\n", cmd,keyring_erreur(r));
    return r; 
}

static int lire_texte(const char *question, char *dst, size_t taille) {
    printf("%s", question);
    fflush(stdout);
    if (fgets(dst, (int)taille, stdin) == NULL) return -1;
    size_t n = strlen(dst);
    if (n && dst[n-1] == '\n') dst[n-1] = '\0';
    else {
        int ch; 
        while ((ch = getchar()) != '\n' && ch != EOF) {} 
        return -1; 
    }
    if (strchr(dst, '\r') != NULL || strchr(dst, '|') != NULL) return -1;
    return 0;
}

int cmd_addcontact(KeyRing *kr, int argc, char **argv) {
    if (!kr || !argv) return KR_ERR_PTR;
    if (argc != 2) return usage("addcontact <id>");

    char nom[TEXTE_MAX], prenom[TEXTE_MAX], commentaire[TEXTE_MAX];
    if (lire_texte("Nom : ", nom, sizeof nom) || lire_texte("Prenom : ", prenom, sizeof prenom) || lire_texte("Commentaire : ", commentaire, sizeof commentaire)) {
        aff_erreur("addcontact : saisie invalide ou trop longue\n"); 
        return KR_ERR_BADTEXT;
    }
    int r = contact_add(kr, argv[1], nom, prenom, commentaire);
    if (r != KR_OK) return erreur_contact("addcontact", r);
    aff_succes("Contact '%s' ajoute.\n", argv[1]); 
    return CMD_OK;
}

int cmd_modifycontact(KeyRing *kr, int argc, char **argv) {
    if (!kr || !argv) return KR_ERR_PTR;
    if (argc != 2) return usage("modifycontact <id>");

    Contact *c = contact_find(kr, argv[1]);
    if (!c) return erreur_contact("modifycontact", KR_ERR_NOTFOUND);

    char choix[16], valeur[TEXTE_MAX];
    printf("Contact : %s\n1. Modifier le nom (%s)\n2. Modifier le prenom (%s)\n3. Modifier le commentaire (%s)\n4. Retour\n",
           c->id, c->nom, c->prenom, c->commentaire);
    if (lire_texte("Votre choix : ", choix, sizeof choix) != 0) return KR_ERR_BADTEXT;
    if (strcmp(choix, "4") == 0) return CMD_OK;
    if (strcmp(choix, "1") != 0 && strcmp(choix, "2") != 0 && strcmp(choix, "3") != 0) return usage("choix : 1, 2, 3 ou 4");
    if (lire_texte("Nouvelle valeur : ", valeur, sizeof valeur) != 0) {
        aff_erreur("modifycontact : saisie invalide ou trop longue\n");
        return KR_ERR_BADTEXT;
    }

    char nom[TEXTE_MAX], prenom[TEXTE_MAX], commentaire[TEXTE_MAX];
    strcpy(nom, c->nom); strcpy(prenom, c->prenom); strcpy(commentaire, c->commentaire);
    if (strcmp(choix, "1") == 0) strcpy(nom, valeur);
    else if (strcmp(choix, "2") == 0) strcpy(prenom, valeur);
    else strcpy(commentaire, valeur);
    int r = contact_modify(kr, argv[1], nom, prenom, commentaire);
    if (r != KR_OK) return erreur_contact("modifycontact", r);
    aff_succes("Contact '%s' modifie.\n", argv[1]); return CMD_OK;
}

int cmd_listcontacts(KeyRing *kr, int argc, char **argv) {
    if (!kr || !argv) return KR_ERR_PTR;
    if (argc > 2) return usage("listcontacts [<idcontact ou nom>]");
    contact_list(kr, argc == 2 ? argv[1] : NULL); 
    return CMD_OK;
}

int cmd_addkeys(KeyRing *kr, int argc, char **argv) {
    if (!kr || !argv) return KR_ERR_PTR;
    if (argc != 2) return usage("addkeys <idcontact>");
    
    Contact *c = contact_find(kr, argv[1]);
    if (!c) c = contact_find_name(kr, argv[1]);
    if (!c) return erreur_contact("addkeys", KR_ERR_NOTFOUND);

    char id[NAME_MAX_SIZE], type[TYPE_MAX_SIZE], fichier[256];
    if (lire_texte("Identifiant de la cle : ", id, sizeof id) || lire_texte("Type (crypt/sign) : ", type, sizeof type) || lire_texte("Fichier de la cle publique : ", fichier, sizeof fichier)) {
        aff_erreur("addkeys : saisie invalide\n"); 
        return KR_ERR_BADTEXT;
    }

    rsaKey_t pub;
    if (pubkey_import(fichier, &pub) != 0) { 
        aff_erreur("addkeys : impossible de lire la cle publique\n"); 
        return -1; 
    }
    int r = contact_addkey(kr, c->id, id, type, &pub);
    if (r != KR_OK) return erreur_contact("addkeys", r);
    aff_succes("Cle '%s' ajoutee au contact '%s'.\n", id, c->id); 
    return CMD_OK;
}

int cmd_rmcontact(KeyRing *kr, int argc, char **argv) {
    if (!kr || !argv) return KR_ERR_PTR;
    if (argc != 2) return usage("rmcontact <id>");

    int r = contact_remove(kr, argv[1]);
    if (r != KR_OK) return erreur_contact("rmcontact", r);
    aff_succes("Contact '%s' et ses cles supprimes.\n", argv[1]); 
    return CMD_OK;
}

