#include <stdio.h>
#include <string.h>
#include "interpreter.h"

#include "cmd_keys.h"
static int echecs = 0;

static void check(const char *nom, int condition) {
    printf("%s  %s\n", condition ? "OK   " : "ECHEC", nom);
    if (!condition) echecs++;
}

int main(void) {
    char *argv[MAX_ARGS];

    // --- découpage d'une ligne ---
    char l1[] = "crypt a.txt b.enc bob\n";
    int argc = decouper_ligne(l1, argv, MAX_ARGS);
    check("4 mots", argc == 4);
    check("argv[0] = crypt", strcmp(argv[0], "crypt") == 0);
    check("argv[2] = b.enc", strcmp(argv[2], "b.enc") == 0);
    check("argv[3] = bob", strcmp(argv[3], "bob") == 0);

    char l2[] = "\n";
    check("ligne vide : 0 mot", decouper_ligne(l2, argv, MAX_ARGS) == 0);

    char l3[] = "   listkeys    bob  \n";
    argc = decouper_ligne(l3, argv, MAX_ARGS);
    check("espaces en trop : 2 mots", argc == 2);
    check("argv[0] = listkeys", strcmp(argv[0], "listkeys") == 0);
    check("argv[1] = bob", strcmp(argv[1], "bob") == 0);

    char l4[] = "a b c d e";
    check("limite de 3 mots", decouper_ligne(l4, argv, 3) == 3);

    // --- la boucle complète ---
    // on écrit dans un fichier ce que l'utilisateur taperait,
    // puis on redirige l'entrée du programme vers ce fichier
    KeyRing kr;
    keyring_init(&kr);

    FILE *f = fopen("tmp_entree.txt", "w");
    fputs("newkeys bob crypt\n"     // crée la clef bob
          "\n"                      // ligne vide : ignorée
          "foo bar\n"               // commande inconnue : message d'erreur
          "newkeys alice crypt\n"   // crée la clef alice
          "quit\n"                  // la boucle s'arrête ici
          "newkeys apres quit\n",   // ne doit jamais être exécutée
          f);
    fclose(f);

    freopen("tmp_entree.txt", "r", stdin);
    check("la boucle se termine", interpreter_run(&kr) == 0);
    check("bob a été créé",       keyring_find(&kr, "bob") != NULL);
    check("alice a été créée",    keyring_find(&kr, "alice") != NULL);
    check("rien après quit",      keyring_find(&kr, "apres") == NULL);

    keyring_free(&kr);
    remove("tmp_entree.txt");
    // --- ligne trop longue ---
    // 255 espaces, puis une commande cachée à la suite : si la ligne est mal gérée,
    // la commande cachée sera exécutée par erreur
    KeyRing kr2;
    keyring_init(&kr2);

    char longue[400];
    memset(longue, ' ', 255);
    strcpy(longue + 255, "newkeys piege crypt\n");

    FILE *g = fopen("tmp_longue.txt", "w");
    fputs(longue, g);
    fputs("newkeys ok crypt\n", g);
    fputs("quit\n", g);
    fclose(g);

    freopen("tmp_longue.txt", "r", stdin);
    interpreter_run(&kr2);
    check("ligne trop longue : ignoree en entier", keyring_find(&kr2, "piege") == NULL);
    check("la commande suivante est executee",     keyring_find(&kr2, "ok") != NULL);

    keyring_free(&kr2);
    remove("tmp_longue.txt");
        // test : la commande help
    char *aide1[] = { "help" };
    char *aide2[] = { "help", "foo" };
    check("help : succes",                    cmd_help(NULL, 1, aide1) == CMD_OK);
    check("help avec un mot en trop refuse",  cmd_help(NULL, 2, aide2) == CMD_ERR_USAGE);
    // --- bilan ---
    if (echecs == 0) printf("tous les tests passent\n");
    else printf("%d echec(s)\n", echecs);
    return echecs;
}