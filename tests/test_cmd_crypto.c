// tests de crypt / uncrypt (phase 3)
//
// Idée : on joue le rôle d'un utilisateur. Alice écrit un message, le chiffre
// pour Bob avec la commande crypt, puis Bob le déchiffre avec uncrypt.
// On vérifie qu'on retrouve le message d'Alice, et que les erreurs sont refusées.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "interpreter.h"
#include "cmd_crypto.h"
#include "keyring.h"
#include "io_utils.h"
#include "rsa_bytes.h"

static int echecs = 0;

static void check(const char *nom, int condition) {
    printf("%s  %s\n", condition ? "OK   " : "ECHEC", nom);
    if (!condition) echecs++;
}

// écrit un texte dans un fichier
static void ecrire_texte(const char *chemin, const char *texte) {
    write_file(chemin, (const uint8_t *)texte, strlen(texte));
}

// vrai si le fichier contient exactement ce texte
static int contient(const char *chemin, const char *texte) {
    uint8_t *lu = NULL;
    size_t n = 0;
    if (read_file(chemin, &lu, &n) != 0) return 0;
    int ok = (n == strlen(texte) && (n == 0 || memcmp(lu, texte, n) == 0));
    free(lu);
    return ok;
}

// taille d'un fichier (-1 s'il n'existe pas)
static long taille(const char *chemin) {
    uint8_t *lu = NULL;
    size_t n = 0;
    if (read_file(chemin, &lu, &n) != 0) return -1;
    free(lu);
    return (long)n;
}

// chiffre puis déchiffre un message avec bob ; vrai si on retrouve le message
static int aller_retour(KeyRing *kr, const char *message) {
    char *c[] = { "crypt", "bob", "tmp_msg.txt", "tmp_msg.enc" };
    char *u[] = { "uncrypt", "bob", "tmp_msg.enc", "tmp_msg.dec" };
    ecrire_texte("tmp_msg.txt", message);
    if (cmd_crypt(kr, 4, c) != CMD_OK) return 0;
    if (cmd_uncrypt(kr, 4, u) != CMD_OK) return 0;
    return contient("tmp_msg.dec", message);
}

int main(void) {
    KeyRing kr;
    keyring_init(&kr);
    keyring_new(&kr, "bob", "crypt");
    keyring_new(&kr, "alice", "crypt");

    // --- 1) un message chiffré pour Bob ---
    const char *msg = "Salut Bob, rdv a 18h devant la fac !";
    ecrire_texte("tmp_msg.txt", msg);

    char *c1[] = { "crypt", "bob", "tmp_msg.txt", "tmp_msg.enc" };
    check("crypt bob : succes", cmd_crypt(&kr, 4, c1) == CMD_OK);
    // 36 octets -> 9 blocs complets + 1 bloc de bourrage = 10 blocs de 8 octets
    check("fichier chiffre : 80 octets", taille("tmp_msg.enc") == 80);
    check("le chiffre n'est pas le message", !contient("tmp_msg.enc", msg));

    char *u1[] = { "uncrypt", "bob", "tmp_msg.enc", "tmp_msg.dec" };
    check("uncrypt bob : succes", cmd_uncrypt(&kr, 4, u1) == CMD_OK);
    check("Bob retrouve le message d'Alice", contient("tmp_msg.dec", msg));

    // --- 2) messages variés : tous doivent revenir identiques ---
    check("message vide",           aller_retour(&kr, ""));
    check("un seul caractere",      aller_retour(&kr, "a"));
    check("accents et emoji",       aller_retour(&kr, "Café ☕ à 18h, on se retrouve ?"));
    check("espaces et retours",     aller_retour(&kr, "ligne 1\nligne 2\n\n  fin  "));

    char gros[2001];
    for (int i = 0; i < 2000; i++) gros[i] = 'a' + (i % 26);
    gros[2000] = '\0';
    check("message de 2000 lettres", aller_retour(&kr, gros));

    // --- 3) la mauvaise personne ne peut pas lire ---
    // le message chiffré pour Bob (tmp_msg.enc) est déchiffré avec la clef d'Alice
    char *u2[] = { "uncrypt", "alice", "tmp_msg.enc", "tmp_alice.dec" };
    int r = cmd_uncrypt(&kr, 4, u2);
    check("alice ne lit pas le message de bob",
          r != CMD_OK || !contient("tmp_alice.dec", msg));

    // --- 4) erreurs d'utilisation ---
    char *inconnu[]  = { "crypt", "zoe", "tmp_msg.txt", "tmp_x.enc" };
    check("id inconnue refusee", cmd_crypt(&kr, 4, inconnu) == KR_ERR_NOTFOUND);

    char *court[]    = { "crypt", "bob", "tmp_msg.txt" };
    check("crypt avec 3 mots refuse", cmd_crypt(&kr, 3, court) == CMD_ERR_USAGE);

    char *long5[]    = { "crypt", "bob", "a", "b", "c" };
    check("crypt avec 5 mots refuse", cmd_crypt(&kr, 5, long5) == CMD_ERR_USAGE);

    char *absent[]   = { "crypt", "bob", "n_existe_pas.txt", "tmp_x.enc" };
    check("fichier a chiffrer introuvable", cmd_crypt(&kr, 4, absent) == RSA_ERR_IO);

    char *dec_abs[]  = { "uncrypt", "bob", "n_existe_pas.enc", "tmp_x.dec" };
    check("fichier a dechiffrer introuvable", cmd_uncrypt(&kr, 4, dec_abs) == RSA_ERR_IO);

    char *trop_court[] = { "uncrypt", "bob", "tmp_msg.txt", "tmp_x.dec" };
    // tmp_msg.txt fait 36 octets : pas un multiple de 8, donc pas un fichier chiffre valide
    check("fichier non chiffre refuse", cmd_uncrypt(&kr, 4, trop_court) != CMD_OK);

    check("crypt avec annuaire NULL", cmd_crypt(NULL, 4, c1) == KR_ERR_PTR);

    // --- 5) scénario complet, comme un vrai utilisateur dans le shell ---
    ecrire_texte("tmp_scenario.txt", "mot de passe du wifi : pas ici !");
    FILE *f = fopen("tmp_entree.txt", "w");
    fputs("crypt alice tmp_scenario.txt tmp_scenario.enc\n"
          "uncrypt alice tmp_scenario.enc tmp_scenario.dec\n"
          "quit\n", f);
    fclose(f);
    freopen("tmp_entree.txt", "r", stdin);
    interpreter_run(&kr);
    check("scenario dans le shell : message retrouve",
          contient("tmp_scenario.dec", "mot de passe du wifi : pas ici !"));

    // --- ménage ---
    keyring_free(&kr);
    remove("tmp_msg.txt");   remove("tmp_msg.enc");  remove("tmp_msg.dec");
    remove("tmp_alice.dec"); remove("tmp_x.enc");    remove("tmp_x.dec");
    remove("tmp_scenario.txt"); remove("tmp_scenario.enc"); remove("tmp_scenario.dec");
    remove("tmp_entree.txt");

    if (echecs == 0) printf("tous les tests passent\n");
    else printf("%d echec(s)\n", echecs);
    return echecs;
}