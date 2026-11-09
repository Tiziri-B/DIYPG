#include <stdio.h>
#include <string.h>
#include "cmd_crypto.h"
#include "rsa_file.h"
#include "b64_file.h"
#include "affichage.h"

// le sujet exige une clef de type "crypt" pour chiffrer et déchiffrer
#define TYPE_ATTENDU "crypt"

static int usage(const char *texte) {
    aff_erreur("usage : %s\n", texte);
    return CMD_ERR_USAGE;
}

// message d'erreur lisible pour les codes de retour de la partie RSA
static const char *texte_rsa(int code) {
    switch (code) {
        case RSA_ERR_ARG:     return "argument invalide";
        case RSA_ERR_SMALL_N: return "modulo N trop petit";
        case RSA_ERR_RANGE:   return "valeur hors limites (fichier ou clef incorrects)";
        case RSA_ERR_MEM:     return "memoire insuffisante";
        case RSA_ERR_IO:      return "lecture ou ecriture du fichier impossible";
        default:              return "erreur inconnue";
    }
}

int cmd_crypt(KeyRing *kr, int argc, char **argv)
{
    if (kr == NULL || argv == NULL) return KR_ERR_PTR;
    // il faut exactement 4 mots : crypt <fichier_clair> <fichier_chiffre> <keyid>
    if (argc != 4) return usage("crypt <fichier_clair> <fichier_chiffre> <keyid>");

    // on cherche la clef de l'id donne (c'est le dernier mot)
    KeyEntry *e = keyring_find(kr, argv[3]);
    if (e == NULL) {
        aff_erreur("crypt : %s\n", keyring_erreur(KR_ERR_NOTFOUND));
        return KR_ERR_NOTFOUND;
    }
    if (strcmp(e->type, TYPE_ATTENDU) != 0) {
        aff_erreur("crypt : la clef '%s' est de type %s (il faut une clef de type %s)\n",
                   argv[3], e->type, TYPE_ATTENDU);
        return KR_ERR_TYPAGE;
    }

    int r = chiffrer_fichier_bloc(argv[1], argv[2], &e->keys.pubKey);
    if (r != RSA_OK) {
        aff_erreur("crypt : %s\n", texte_rsa(r));
        return r;
    }

    aff_succes("'%s' chiffre dans '%s' avec la clef '%s'\n", argv[1], argv[2], argv[3]);
    return CMD_OK;
}

int cmd_uncrypt(KeyRing *kr, int argc, char **argv)
{
    if (kr == NULL || argv == NULL) return KR_ERR_PTR;
    // il faut exactement 4 mots : uncrypt <fichier_chiffre> <fichier_clair> <keyid>
    if (argc != 4) return usage("uncrypt <fichier_chiffre> <fichier_clair> <keyid>");

    KeyEntry *e = keyring_find(kr, argv[3]);
    if (e == NULL) {
        aff_erreur("uncrypt : %s\n", keyring_erreur(KR_ERR_NOTFOUND));
        return KR_ERR_NOTFOUND;
    }
    if (strcmp(e->type, TYPE_ATTENDU) != 0) {
        aff_erreur("uncrypt : la clef '%s' est de type %s (il faut une clef de type %s)\n",
                   argv[3], e->type, TYPE_ATTENDU);
        return KR_ERR_TYPAGE;
    }

    int r = dechiffrer_fichier_bloc(argv[1], argv[2], &e->keys.privKey);
    if (r != RSA_OK) {
        aff_erreur("uncrypt : %s\n", texte_rsa(r));
        return r;
    }

    aff_succes("'%s' dechiffre dans '%s' avec la clef '%s'\n", argv[1], argv[2], argv[3]);
    return CMD_OK;
}

int cmd_bin2b64(KeyRing *kr, int argc, char **argv) {
    (void)kr;    // cette commande n'utilise pas l'annuaire
    if (argv == NULL) return KR_ERR_PTR;
    if (argc != 3) return usage("bin-2b64 <fichier_bin> <fichier_b64>");

    if (fichier_vers_b64(argv[1], argv[2]) != 0) {
        aff_erreur("bin-2b64 : conversion impossible (fichier introuvable ou illisible)\n");
        return -1;
    }

    aff_succes("'%s' converti en base64 dans '%s'\n", argv[1], argv[2]);
    return CMD_OK;
}

int cmd_b642bin(KeyRing *kr, int argc, char **argv) {
    (void)kr;    // cette commande n'utilise pas l'annuaire
    if (argv == NULL) return KR_ERR_PTR;
    if (argc != 3) return usage("b64-2bin <fichier_b64> <fichier_bin>");

    if (b64_vers_fichier(argv[1], argv[2]) != 0) {
        aff_erreur("b64-2bin : conversion impossible (fichier introuvable ou base64 invalide)\n");
        return -1;
    }

    aff_succes("'%s' (base64) converti en binaire dans '%s'\n", argv[1], argv[2]);
    return CMD_OK;
}