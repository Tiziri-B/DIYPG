#include <stdio.h>
#include "cmd_keys.h"
#include <string.h>
#include "cmd_crypto.h"
#include "interpreter.h"

int decouper_ligne(char *ligne, char **argv,int max )
{
    int argc=0;
    char *mot = strtok(ligne, " \t\r\n");//separateur avec des espaces
    while (mot !=NULL && argc < max)
    {
        argv[argc]=mot;
        argc++;
        mot = strtok(NULL, " \t\r\n"); 
    }
    return argc;
}
//la commande tapee par lutilisateur doit correspondre a une fontion 
typedef int (*commande_fn)(KeyRing *kr, int argc, char **argv);

typedef struct {
    const char *nom;
    commande_fn fonction;
} Commande;
static void afficher_bienvenue(void) {
    if (!isatty(STDOUT_FILENO)) return;      // pas dans les tests ni en redirection
    printf("DIYPG - Do It Yourself Privacy Guard\n");
    printf("tape 'quit' pour sortir\n\n");
}
// table de routage (se termine par une case  de NULL
static const Commande TABLE[] = {
    { "newkeys",  cmd_newkeys  },
    { "listkeys", cmd_listkeys },
    { "rmkeys",   cmd_rmkeys   },
    { "show",     cmd_show     },
    { "crypt",    cmd_crypt    },
    { "uncrypt",  cmd_uncrypt  },
    { "bin-2b64", cmd_bin2b64 },
    { "b64-2bin", cmd_b642bin },
    { NULL,       NULL         }
};

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
        printf("diypg> ");
        fflush(stdout);

        // fgets renvoie NULL a la fin
        if (fgets(ligne, sizeof ligne, stdin) == NULL) {
            break;
        }

        int argc = decouper_ligne(ligne, argv, MAX_ARGS);
        if (argc == 0) {
            continue;                       // ligne vide : on redemande
        }
        if (strcmp(argv[0], "quit") == 0) {
            break; //on quite
        }

        commande_fn f = trouver_commande(argv[0]);
        if (f == NULL) {
            fprintf(stderr, "%s : commande inconnue\n", argv[0]);
            //ne fait pas partie de la table 
            continue;
        }
        f(kr, argc, argv);
        //on appele la fonction
    }
    return 0;}
