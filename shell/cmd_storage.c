#include <stdio.h>
#include "cmd_storage.h"
#include "storage.h"
#include "affichage.h"

static int usage(const char *texte) {
    aff_erreur("usage : %s\n", texte);
    return CMD_ERR_USAGE;
}

int cmd_save(KeyRing *kr, int argc, char **argv) {
    if (kr == NULL || argv == NULL) return KR_ERR_PTR;
    if (argc != 1 && argc != 2) return usage("save [<fichier>]");

    const char *fichier = (argc == 2) ? argv[1] : FICHIER_PAR_DEFAUT;
    if (storage_save(kr, fichier) != 0) return -1;

    aff_succes("annuaire sauvegarde dans '%s' (%d cle(s))\n", fichier, kr->count);
    return CMD_OK;
}

int cmd_load(KeyRing *kr, int argc, char **argv) {
    if (kr == NULL || argv == NULL) return KR_ERR_PTR;
    if (argc != 1 && argc != 2) return usage("load [<fichier>]");

    const char *fichier = (argc == 2) ? argv[1] : FICHIER_PAR_DEFAUT;
    if (storage_load(kr, fichier) != 0) return -1;

    aff_succes("annuaire charge depuis '%s' (%d cle(s))\n", fichier, kr->count);
    return CMD_OK;
}

int cmd_savepub(KeyRing *kr, int argc, char **argv) {
    if (kr == NULL || argv == NULL) return KR_ERR_PTR;
    if (argc != 3) return usage("savepub <keyid> <fichier>");

    if (storage_savepub(kr, argv[1], argv[2]) != 0) return -1;

    aff_succes("cle publique de '%s' ecrite en base64 dans '%s'\n", argv[1], argv[2]);
    return CMD_OK;
}

