#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "interpreter.h"
#include "affichage.h"
#include "cmd_keys.h"
#include "cmd_crypto.h"
#include "cmd_storage.h"

// couleurs (codes ANSI), utilisées seulement dans un vrai terminal
#define NOM_PROMPT     "diypg"
#define COULEUR_PROMPT "\033[1;36m"   // cyan gras
#define COULEUR_FIN    "\033[0m"      // retour à la normale

// vrai si la sortie est un vrai terminal (pas une redirection ni un test)
static int terminal(void) {
    return isatty(STDOUT_FILENO);
}

// affiche "diypg> " (en cyan si on est dans un terminal)
static void afficher_prompt(void) {
    if (terminal()) {
        printf("%s%s>%s ", COULEUR_PROMPT, NOM_PROMPT, COULEUR_FIN);
    } else {
        printf("%s> ", NOM_PROMPT);
    }
    fflush(stdout);                 // pour que le prompt apparaisse tout de suite
}

// message de bienvenue : change selon l'heure, et utilise ton nom d'utilisateur
static void afficher_bienvenue(void) {
    if (!terminal()) return;        // pas de bienvenue dans les tests

    time_t t = time(NULL);
    struct tm *h = localtime(&t);

    const char *salut = "Bonsoir";
    if (h != NULL && h->tm_hour < 12) salut = "Bonjour";
    else if (h != NULL && h->tm_hour < 18) salut = "Bon apres-midi";

    const char *nom = getenv("USER");
    if (nom == NULL) nom = "toi";

    aff_titre("%s %s, bienvenue dans DIYPG - Do It Yourself Privacy Guard\n", salut, nom);
    aff_info("tape 'quit' pour sortir\n\n");
}

int decouper_ligne(char *ligne, char **argv, int max)
{
    int argc = 0;
    char *mot = strtok(ligne, " \t\r\n");   // séparateurs : espace, tabulation...
    while (mot != NULL && argc < max)
    {
        argv[argc] = mot;
        argc++;
        mot = strtok(NULL, " \t\r\n");
    }
    return argc;
}

// la commande tapée par l'utilisateur doit correspondre à une fonction
typedef int (*commande_fn)(KeyRing *kr, int argc, char **argv);

typedef struct {
    const char *nom;
    commande_fn fonction;
    const char *syntaxe;       // ce qu'on tape (pour l'aide)
    const char *description;   // ce que ça fait (pour l'aide)
} Commande;
// table de routage (se termine par une case de NULL)
static const Commande TABLE[] = {
    { "newkeys",  cmd_newkeys,  "newkeys <keyid> <crypt|sign>",           "genere une paire de clefs"      },
    { "listkeys", cmd_listkeys, "listkeys [<keyid>]",                     "liste les clefs (ou une seule)" },
    { "rmkeys",   cmd_rmkeys,   "rmkeys <keyid>",                         "supprime une clef"              },
    { "show",     cmd_show,     "show <keyid> [pub] [priv]",              "affiche une clef"               },
    { "crypt",    cmd_crypt,    "crypt <keyid> <clair> <chiffre>",        "chiffre un fichier"             },
    { "uncrypt",  cmd_uncrypt,  "uncrypt <keyid> <chiffre> <clair>",      "dechiffre un fichier"           },
    { "bin-2b64", cmd_bin2b64,  "bin-2b64 <fichier_bin> <fichier_b64>",   "convertit un fichier en base64" },
    { "b64-2bin", cmd_b642bin,  "b64-2bin <fichier_b64> <fichier_bin>",   "convertit du base64 en fichier" },
    { "save",     cmd_save,     "save [<fichier>]",                       "sauvegarde l'annuaire"          },
    { "load",     cmd_load,     "load [<fichier>]",                       "charge une sauvegarde"          },
    { "savepub",  cmd_savepub,  "savepub <keyid> <fichier>",              "ecrit une clef publique (base64)" },
    { "help",     cmd_help,     "help",                                   "affiche cette aide"             },
    { NULL,       NULL,         NULL,                                     NULL                             }
};
int cmd_help(KeyRing *kr, int argc, char **argv) {
    (void)kr;       // ces deux arguments ne servent pas ici
    (void)argv;
    if (argc != 1) {
        aff_erreur("usage : help\n");
        return CMD_ERR_USAGE;
    }

    aff_titre("Commandes disponibles :\n");
    for (int i = 0; TABLE[i].nom != NULL; i++) {
        printf("  %-38s ", TABLE[i].syntaxe);
        aff_info("%s\n", TABLE[i].description);
    }
    printf("  %-38s ", "quit");
    aff_info("quitte le programme\n");
    return CMD_OK;
}
// cherche le nom dans la table
static commande_fn trouver_commande(const char *nom) {
    for (int i = 0; TABLE[i].nom != NULL; i++) {
        if (strcmp(TABLE[i].nom, nom) == 0) {
            return TABLE[i].fonction;
        }
    }
    return NULL;
}

int interpreter_run(KeyRing *kr) {
    char ligne[LIGNE_MAX];
    char *argv[MAX_ARGS];

    afficher_bienvenue();

    while (1) {
        afficher_prompt();

        // fgets renvoie NULL à la fin de l'entrée
        if (fgets(ligne, sizeof ligne, stdin) == NULL) {
            break;
        }

        // ligne trop longue  fgets s'est arrrete avant la fin de la ligne
        if (strchr(ligne, '\n') == NULL && !feof(stdin)) {
            aff_erreur("ligne trop longue (%d caracteres maximum)\n", LIGNE_MAX - 2);
            int c;
            while ((c = getchar()) != '\n' && c != EOF) { }   // on jette le reste
            continue;
        }

        int argc = decouper_ligne(ligne, argv, MAX_ARGS);
        if (argc == 0) {
            continue;                       // ligne vide : on redemande
        }
        if (strcmp(argv[0], "quit") == 0) {
            break;                          // on quitte
        }

        commande_fn f = trouver_commande(argv[0]);
        if (f == NULL) {
            aff_erreur("%s : commande inconnue\n", argv[0]);   // pas dans la table
            aff_info("tape 'help' pour voir les commandes\n");
            continue;
        }
        f(kr, argc, argv);                  // on appelle la fonction
    }
    return 0;
}