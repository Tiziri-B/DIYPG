#include <stdio.h>
#include "cmd_crypto.h"
#include "rsa_file.h"
#include "b64_file.h"
static int usage(const char *texte) {
    fprintf(stderr, "usage : %s\n", texte);
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
    //si n a pas exactement 4 mots donc le nombre darguments est incorrect
    if (argc != 4) return usage("crypt <keyid> <fichier_clair> <fichier_chiffre>");
    //oncherche la clef de l'id donne
    KeyEntry *e = keyring_find(kr, argv[1]);
    if (e == NULL) {
        fprintf(stderr, "crypt : %s\n", keyring_erreur(KR_ERR_NOTFOUND));
        return KR_ERR_NOTFOUND;
    }
    int r = chiffrer_fichier_bloc(argv[2], argv[3], &e->keys.pubKey);
    if (r != RSA_OK) {
        fprintf(stderr, "crypt : %s\n", texte_rsa(r));
        return r;
    }
    printf("'%s' chiffre dans '%s' avec la clef '%s'\n", argv[2], argv[3], argv[1]);
    return CMD_OK;

}
int cmd_uncrypt(KeyRing *kr, int argc, char **argv)
{
    if (kr == NULL || argv == NULL) return KR_ERR_PTR;
    //si n a pas exactement 4 mots donc le nombre darguments est incorrect
    if (argc != 4) return usage("uncrypt <keyid> <fichier_chiffre> <fichier_clair>");
    //oncherche la clef de l'id donne
    KeyEntry *e = keyring_find(kr, argv[1]);
    if (e == NULL) {
        fprintf(stderr, "uncrypt : %s\n", keyring_erreur(KR_ERR_NOTFOUND));
        return KR_ERR_NOTFOUND;
    }
    int r = dechiffrer_fichier_bloc(argv[2], argv[3], &e->keys.privKey);
    if (r != RSA_OK) {
        fprintf(stderr, "uncrypt : %s\n", texte_rsa(r));
        return r;
    }
    printf("'%s' dechiffre dans '%s' avec la clef '%s'\n", argv[2], argv[3], argv[1]);
    return CMD_OK;


}
int cmd_bin2b64(KeyRing *kr, int argc, char **argv) {
    (void)kr;    // cette commande n'utilise pas l'annuaire
    if (argv == NULL) return KR_ERR_PTR;
    if (argc != 3) return usage("bin-2b64 <fichier_bin> <fichier_b64>");

    if (fichier_vers_b64(argv[1], argv[2]) != 0) {
        fprintf(stderr, "bin-2b64 : conversion impossible (fichier introuvable ou illisible)\n");
        return -1;
    }

    printf("'%s' converti en base64 dans '%s'\n", argv[1], argv[2]);
    return CMD_OK;
}
int cmd_b642bin(KeyRing *kr, int argc, char **argv) {
    (void)kr;    // cette commande n'utilise pas l'annuaire
    if (argv == NULL) return KR_ERR_PTR;
    if (argc != 3) return usage("b64-2bin <fichier_b64> <fichier_bin>");

    if (b64_vers_fichier(argv[1], argv[2]) != 0) {
        fprintf(stderr, "b64-2bin : conversion impossible (fichier introuvable ou base64 invalide)\n");
        return -1;
    }

    printf("'%s' (base64) converti en binaire dans '%s'\n", argv[1], argv[2]);
    return CMD_OK;
}