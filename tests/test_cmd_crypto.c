// tests de crypt / uncrypt / bin-2b64 / b64-2bin (phase 3)
//
// Idée : on joue le rôle d'un utilisateur. Alice écrit un message, le chiffre
// pour Bob avec la commande crypt, puis Bob le déchiffre avec uncrypt.
// On vérifie qu'on retrouve le message d'Alice, et que les erreurs sont refusées.
// On teste aussi les conversions base64.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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

// remplace les clefs générées par des clefs connues (N > 2^32),
// pour que le test ne dépende pas du générateur aléatoire
static void imposer_cles(KeyRing *kr, const char *id, uint64_t N, uint64_t E, uint64_t D) {
    KeyEntry *e = keyring_find(kr, id);
    e->keys.pubKey.N  = N;  e->keys.pubKey.E  = E;
    e->keys.privKey.N = N;  e->keys.privKey.E = D;
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

// vrai si le fichier commence par ce texte
static int commence_par(const char *chemin, const char *debut) {
    uint8_t *lu = NULL;
    size_t n = 0;
    if (read_file(chemin, &lu, &n) != 0) return 0;
    int ok = (n >= strlen(debut) && memcmp(lu, debut, strlen(debut)) == 0);
    free(lu);
    return ok;
}

// vrai si le fichier ne contient que des caractères base64 (et fins de ligne)
static int est_base64(const char *chemin) {
    uint8_t *lu = NULL;
    size_t n = 0;
    if (read_file(chemin, &lu, &n) != 0) return 0;
    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        char c = (char)lu[i];
        int bon = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                  || c == '+' || c == '/' || c == '=' || c == '\n' || c == '\r';
        if (!bon) ok = 0;
    }
    free(lu);
    return ok;
}

// vrai si le fichier contient exactement ces octets
static int memes_octets(const char *chemin, const uint8_t *octets, size_t n) {
    uint8_t *lu = NULL;
    size_t m = 0;
    if (read_file(chemin, &lu, &m) != 0) return 0;
    int ok = (m == n && (n == 0 || memcmp(lu, octets, n) == 0));
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
    // clefs fixes (deux paires RSA valides avec N > 2^32)
    imposer_cles(&kr, "bob",   1000036000099ULL, 65537ULL, 983264276609ULL);
    imposer_cles(&kr, "alice", 1000238014157ULL, 65537ULL, 702135554273ULL);

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
    // on chiffre le message pour Bob dans un fichier à part, puis Alice essaie de le lire
    ecrire_texte("tmp_msg.txt", msg);
    char *c3[] = { "crypt", "bob", "tmp_msg.txt", "tmp_pourbob.enc" };
    check("crypt pour bob : succes", cmd_crypt(&kr, 4, c3) == CMD_OK);

    char *u2[] = { "uncrypt", "alice", "tmp_pourbob.enc", "tmp_alice.dec" };
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

    // un fichier de 11 octets : pas un multiple de 8, donc pas un fichier chiffre valide
    ecrire_texte("tmp_pas_chiffre.txt", "pas chiffre");
    char *trop_court[] = { "uncrypt", "bob", "tmp_pas_chiffre.txt", "tmp_x.dec" };
    check("fichier non chiffre refuse", cmd_uncrypt(&kr, 4, trop_court) == RSA_ERR_RANGE);

    check("crypt avec annuaire NULL", cmd_crypt(NULL, 4, c1) == KR_ERR_PTR);
    // --- clef trop petite pour le chiffrement par blocs ---
    // la petite clef d'exemple du cours : N = 61 x 53 = 3233, E = 17, D = 2753
    keyring_new(&kr, "petit", "crypt");
    imposer_cles(&kr, "petit", 3233ULL, 17ULL, 2753ULL);
    char *cp[] = { "crypt", "petit", "tmp_msg.txt", "tmp_x.enc" };
    check("clef trop petite refusee", cmd_crypt(&kr, 4, cp) == RSA_ERR_SMALL_N);

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

    // --- 6) conversions base64 ---
    // valeur connue : "Hello" s'écrit "SGVsbG8=" en base64
    ecrire_texte("tmp_hello.txt", "Hello");
    char *b1[] = { "bin-2b64", "tmp_hello.txt", "tmp_hello.b64" };
    check("bin-2b64 : succes", cmd_bin2b64(&kr, 3, b1) == CMD_OK);
    check("Hello donne SGVsbG8=", commence_par("tmp_hello.b64", "SGVsbG8="));

    // les 256 valeurs d'octet possibles, de 0 à 255
    uint8_t octets[256];
    for (int i = 0; i < 256; i++) octets[i] = (uint8_t)i;
    write_file("tmp_bin.bin", octets, 256);

    char *b2[] = { "bin-2b64", "tmp_bin.bin", "tmp_bin.b64" };
    char *b3[] = { "b64-2bin", "tmp_bin.b64", "tmp_bin2.bin" };
    check("bin-2b64 sur 256 octets",    cmd_bin2b64(&kr, 3, b2) == CMD_OK);
    check("le resultat est du texte base64", est_base64("tmp_bin.b64"));
    // 256 octets -> 86 groupes de 3 octets, 4 caractères chacun -> 344 caractères au moins
    check("au moins 344 caracteres",    taille("tmp_bin.b64") >= 344);
    check("b64-2bin sur 256 octets",    cmd_b642bin(&kr, 3, b3) == CMD_OK);
    check("on retrouve les 256 octets", memes_octets("tmp_bin2.bin", octets, 256));

    char *b_court[] = { "bin-2b64", "tmp_bin.bin" };
    check("bin-2b64 avec 2 mots refuse", cmd_bin2b64(&kr, 2, b_court) == CMD_ERR_USAGE);
    char *b_court2[] = { "b64-2bin", "tmp_bin.b64" };
    check("b64-2bin avec 2 mots refuse", cmd_b642bin(&kr, 2, b_court2) == CMD_ERR_USAGE);

    char *b_abs[] = { "bin-2b64", "n_existe_pas.bin", "tmp_x.b64" };
    check("bin-2b64 : fichier introuvable", cmd_bin2b64(&kr, 3, b_abs) != CMD_OK);
    char *b_abs2[] = { "b64-2bin", "n_existe_pas.b64", "tmp_x.bin" };
    check("b64-2bin : fichier introuvable", cmd_b642bin(&kr, 3, b_abs2) != CMD_OK);

    // un fichier qui n'est pas du base64 (caractères interdits)
    ecrire_texte("tmp_faux.b64", "@@@@ ceci n'est pas du base64 !!");
    char *b_faux[] = { "b64-2bin", "tmp_faux.b64", "tmp_x.bin" };
    check("b64-2bin : base64 invalide refuse", cmd_b642bin(&kr, 3, b_faux) != CMD_OK);

    // le tout depuis le shell : texte -> base64 -> texte
    FILE *g = fopen("tmp_entree2.txt", "w");
    fputs("bin-2b64 tmp_hello.txt tmp_s.b64\n"
          "b64-2bin tmp_s.b64 tmp_s.txt\n"
          "quit\n", g);
    fclose(g);
    freopen("tmp_entree2.txt", "r", stdin);
    interpreter_run(&kr);
    check("scenario base64 dans le shell : Hello retrouve", contient("tmp_s.txt", "Hello"));

    // --- ménage des fichiers temporaires ---
    keyring_free(&kr);
    remove("tmp_msg.txt");   remove("tmp_msg.enc");  remove("tmp_msg.dec");
    remove("tmp_pourbob.enc"); remove("tmp_alice.dec"); remove("tmp_pas_chiffre.txt");
    remove("tmp_x.enc");     remove("tmp_x.dec");    remove("tmp_x.bin");
    remove("tmp_scenario.txt"); remove("tmp_scenario.enc"); remove("tmp_scenario.dec");
    remove("tmp_entree.txt"); remove("tmp_entree2.txt");
    remove("tmp_hello.txt"); remove("tmp_hello.b64");
    remove("tmp_bin.bin");   remove("tmp_bin.b64");  remove("tmp_bin2.bin");
    remove("tmp_faux.b64");  remove("tmp_s.b64");    remove("tmp_s.txt");

    // --- bilan ---
    if (echecs == 0) printf("tous les tests passent\n");
    else printf("%d echec(s)\n", echecs);
    return echecs;
}