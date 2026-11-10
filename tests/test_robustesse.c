#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../shell/keyring.h"
#include "../shell/interpreter.h"
#include "../shell/cmd_keys.h"
#include "../shell/cmd_crypto.h"
#include "../shell/cmd_storage.h"
#include "io_utils.h"
#include "check.h"

typedef int (*commande)(KeyRing *kr, int argc, char **argv);

// Tape une commande comme dans le shell
// La fonction renvoie ce que la commande renvoie : CMD_OK (0) ou un code d'erreur
static int lancer(commande f, KeyRing *kr, const char *texte) {
    char ligne[300];
    strcpy(ligne, texte);
    char *argv[MAX_ARGS];
    int argc = decouper_ligne(ligne, argv, MAX_ARGS);
    return f(kr, argc, argv);
}

// ecrit un texte dans un fichier
static void ecrire_fichier(const char *chemin, const char *texte) {
    FILE *f = fopen(chemin, "w");
    if (f==NULL) return;
    fputs(texte, f);
    fclose(f);
}

// 1 si les deux fichiers ont exactement le meme contenu
static int memes_octets(const char *a, const char *b) {
    uint8_t *x = NULL, *y = NULL;
    size_t nx = 0, ny = 0;
    int r1 = read_file(a, &x, &nx);
    int r2 = read_file(b, &y, &ny);
    int pareil = r1 == 0 && r2 == 0 && nx == ny && memcmp(x, y, nx) == 0;
    free(x);
    free(y);
    return pareil;
}

static void test_arguments(void) {
    printf("\n***** Mauvais nombre d'arguments *****\n");
    KeyRing kr;
    keyring_init(&kr);
    verifier("newkeys sans argument", lancer(cmd_newkeys, &kr, "newkeys") == CMD_ERR_USAGE);
    verifier("newkeys avec 1 argument",lancer(cmd_newkeys, &kr, "newkeys tiziri") == CMD_ERR_USAGE);
    verifier("newkeys avec 3 arguments",lancer(cmd_newkeys, &kr, "newkeys alice crypt en_trop") == CMD_ERR_USAGE);
    verifier("listkeys avec 2 arguments",lancer(cmd_listkeys, &kr, "listkeys a b") == CMD_ERR_USAGE);
    verifier("rmkeys sans argument",lancer(cmd_rmkeys, &kr, "rmkeys") == CMD_ERR_USAGE);
    verifier("show sans argument",lancer(cmd_show, &kr, "show") == CMD_ERR_USAGE);
    verifier("show avec un mot en trop", lancer(cmd_show, &kr, "show a pub priv en_trop") == CMD_ERR_USAGE);
    verifier("crypt avec 2 arguments",  lancer(cmd_crypt, &kr, "crypt a b") == CMD_ERR_USAGE);
    verifier("uncrypt avec 2 arguments", lancer(cmd_uncrypt, &kr, "uncrypt a b") == CMD_ERR_USAGE);
    verifier("bin-2b64 avec 1 argument", lancer(cmd_bin2b64, &kr, "bin-2b64 a") == CMD_ERR_USAGE);
    verifier("b64-2bin avec 1 argument", lancer(cmd_b642bin, &kr, "b64-2bin a") == CMD_ERR_USAGE);
    verifier("save avec 2 arguments", lancer(cmd_save, &kr, "save a b") == CMD_ERR_USAGE);
    verifier("load avec 2 arguments", lancer(cmd_load, &kr, "load a b") == CMD_ERR_USAGE);
    verifier("savepub avec 1 argument", lancer(cmd_savepub, &kr, "savepub a") == CMD_ERR_USAGE);
    verifier("savepub avec 3 arguments", lancer(cmd_savepub, &kr, "savepub a b c") == CMD_ERR_USAGE);
    verifier("help avec 1 argument", lancer(cmd_help, &kr, "help a") == CMD_ERR_USAGE);
    keyring_free(&kr);
 }

 static void test_identifiants(void) { 
    printf("\n***** Identifiants : invalide, deja pris, introuvable *****\n");
    KeyRing kr;
    keyring_init(&kr);
    verifier("newkeys tiziri crypt : ca marche", lancer(cmd_newkeys, &kr, "newkeys tiziri crypt") == CMD_OK);
    verifier("identifiant deja pris", lancer(cmd_newkeys, &kr, "newkeys tiziri crypt") == KR_ERR_EXISTS);
    verifier("identifiant avec un '/'", lancer(cmd_newkeys, &kr, "newkeys a/b crypt") == KR_ERR_BADID);
    verifier("identifiant trop long (40 caracteres)",
          lancer(cmd_newkeys, &kr, "newkeys xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx crypt") == KR_ERR_BADID);
    verifier("type invalide", lancer(cmd_newkeys, &kr, "newkeys bob truc") == KR_ERR_TYPAGE);
    verifier("rmkeys d'un identifiant inconnu", lancer(cmd_rmkeys, &kr, "rmkeys inconnu") == KR_ERR_NOTFOUND);
    verifier("show d'un identifiant inconnu", lancer(cmd_show, &kr, "show inconnu") == KR_ERR_NOTFOUND);
    verifier("listkeys d'un identifiant inconnu", lancer(cmd_listkeys, &kr, "listkeys inconnu") == KR_ERR_NOTFOUND);
    verifier("show avec une option inconnue", lancer(cmd_show, &kr, "show alice truc") == CMD_ERR_USAGE);
    verifier("crypt : identifiant inconnu", lancer(cmd_crypt, &kr, "crypt inconnu a b") == KR_ERR_NOTFOUND);
    verifier("uncrypt : identifiant inconnu", lancer(cmd_uncrypt, &kr, "uncrypt inconnu a b") == KR_ERR_NOTFOUND);
    verifier("savepub : identifiant inconnu", lancer(cmd_savepub, &kr, "savepub inconnu build/rob.pub") != CMD_OK);
    verifier("rmkeys tiziri : ca marche", lancer(cmd_rmkeys, &kr, "rmkeys tiziri") == CMD_OK);
    verifier("apres rmkeys, show tiziri echoue", lancer(cmd_show, &kr, "show tiziri") == KR_ERR_NOTFOUND);
    keyring_free(&kr);
 }

static void test_fichiers_introuvables(void) {
    printf("\n***** Fichiers introuvables ou incorrects *****\n");
    KeyRing kr;
    keyring_init(&kr); 
    lancer(cmd_newkeys, &kr, "newkeys tiziri crypt");
    ecrire_fichier("build/rob_faux.b64", "ceci n'est pas du base64 !");

    verifier("crypt : fichier introuvable", lancer(cmd_crypt, &kr, "crypt tiziri build/absent.txt build/rob_sortie.enc") != CMD_OK);
    verifier("uncrypt : fichier introuvable", lancer(cmd_uncrypt, &kr, "uncrypt tiziri build/absent.enc build/rob_sortie.txt") != CMD_OK);
    verifier("bin-2b64 : fichier introuvable", lancer(cmd_bin2b64, &kr, "bin-2b64 build/absent.bin build/rob_sortie.b64") != CMD_OK);
    verifier("b64-2bin : fichier introuvable", lancer(cmd_b642bin, &kr, "b64-2bin build/absent.b64 build/rob_sortie.bin") != CMD_OK);
    verifier("b64-2bin : fichier qui n'est pas du base 64", lancer(cmd_b642bin, &kr, "b64-2bin build/rob_faux.b64 build/rob_sortie.bin") != CMD_OK);
    verifier("load : fichier introuvable", lancer(cmd_load, &kr, "load build/absent.dat") != CMD_OK);
    verifier("save : dossier inexistant", lancer(cmd_save, &kr, "save build/pas_de_dossier/k.dat") != CMD_OK);
    verifier("savepub : dossier inexistant", lancer(cmd_savepub, &kr, "savepub alice build/pas_de_dossier/k.pub") != CMD_OK);
    keyring_free(&kr);
}

static void test_type_de_clef(void) {
    printf("\n***** crypt et uncrypt (cle de type crypt) *****\n");
    KeyRing kr;
    keyring_init(&kr);
    ecrire_fichier("build/rob_message.txt", "Bonjour\n");
    
    // k1 est de type crypt
    // k2 est de type sign mais a EXACTEMENT les memes cles que k1
    lancer(cmd_newkeys, &kr, "newkeys k1 crypt");
    lancer(cmd_newkeys, &kr, "newkeys k2 sign");
    keyring_find(&kr, "k2")->keys = keyring_find(&kr, "k1")->keys;
    
    verifier("crypt avec une cle de type crypt : ca marche",
        lancer(cmd_crypt, &kr, "crypt k1 build/rob_message.txt build/rob_message.enc") == CMD_OK);
    verifier("crypt avec une cle de type sign : refuse",
        lancer(cmd_crypt, &kr, "crypt k2 build/rob_message.txt build/rob_message2.enc") != CMD_OK);
    verifier("uncrypt avec une cle de type sign : refuse",
        lancer(cmd_uncrypt, &kr, "uncrypt k2 build/rob_message.enc build/rob_message.out") != CMD_OK);
    keyring_free(&kr);
}

static void test_sauvegarde(void) {
    printf("\n***** Sauvegarde : save, load, savepub *****\n");
    KeyRing kr;
    keyring_init(&kr);
    lancer(cmd_newkeys, &kr, "newkeys tiziri crypt");
    lancer(cmd_newkeys, &kr, "newkeys cylia sign");
    
    verifier("save", lancer(cmd_save, &kr, "save build/rob_s.dat") == CMD_OK);
    struct stat st;
    verifier("le fichier est reserve a son proprietaire (droits 600)",
          stat("build/rob_s.dat", &st) == 0 && (st.st_mode & 0777) == 0600);
    
    lancer(cmd_rmkeys, &kr, "rmkeys tiziri");
    lancer(cmd_rmkeys, &kr, "rmkeys cylia");
    verifier("load", lancer(cmd_load, &kr, "load build/rob_s.dat") == CMD_OK);
    verifier("apres load, les cles tiziri et cylia sont revenues",
          keyring_find(&kr, "tiziri") != NULL && keyring_find(&kr, "cylia") != NULL);
    
    ecrire_fichier("build/rob_abime.dat", "n'importe quoi\n");
    verifier("load d'un fichier abime : refuse", lancer(cmd_load, &kr, "load build/rob_abime.dat") != CMD_OK);
    verifier("et l'annuaire n'a pas change", kr.count == 2 && keyring_find(&kr, "tiziri") != NULL);

    ecrire_fichier("build/rob_petit.dat", "cles 1\ntiziri crypt 65537 33 3 33\ncontacts 0\n");
    verifier("load d'une cle incorrecte (N = 33) : refuse", lancer(cmd_load, &kr, "load build/rob_petit.dat") != CMD_OK);
    verifier("et l'annuaire n'a pas change", kr.count == 2);

    // savepub : 24 caracteres + retour a la ligne = 25
    verifier("savepub", lancer(cmd_savepub, &kr, "savepub tiziri build/rob_tiziri.pub") == CMD_OK);
    char ligne[100] = "";
    FILE *f = fopen("build/rob_tiziri.pub", "r");
    fgets(ligne, sizeof ligne, f);
    fclose(f);
    verifier("le fichier de cle publique contient 24 caracteres + retour a la ligne", strlen(ligne) == 25);
    keyring_free(&kr);
}

static void test_beaucoup_de_cles(void) {
    printf("\n***** Beaucoup de cles (plus que la capacite de depart) *****\n");
    KeyRing kr;
    keyring_init(&kr);
    int ratees = 0;
    for (int i = 1; i <= 12; i++) {
        char texte[50];
        sprintf(texte, "newkeys cle%d crypt", i);
        if (lancer(cmd_newkeys, &kr, texte) != CMD_OK) ratees++;
    }
    verifier("12 cles creees", ratees == 0 && kr.count == 12);
    verifier("save puis load des 12 cles",
          lancer(cmd_save, &kr, "save build/rob_12.dat") == CMD_OK
          && lancer(cmd_load, &kr, "load build/rob_12.dat") == CMD_OK
          && kr.count == 12 && keyring_find(&kr, "cle12") != NULL);
    keyring_free(&kr);
}

static void test_chaine_complete(void) {
    printf("\n***** Le programme complet : chiffrer, dechiffrer, base 64 *****\n");
    KeyRing kr;
    keyring_init(&kr);
    ecrire_fichier("build/rob_message.txt", "Bonjour, ceci est un message secret !\n");

    verifier("newkeys tiziri crypt", lancer(cmd_newkeys, &kr, "newkeys tiziri crypt") == CMD_OK);
    verifier("crypt", lancer(cmd_crypt, &kr, "crypt tiziri build/rob_message.txt build/rob_message.enc") == CMD_OK);
    verifier("uncrypt", lancer(cmd_uncrypt, &kr, "uncrypt tiziri build/rob_message.enc build/rob_message.out") == CMD_OK);
    verifier("le fichier dechiffre est identique au fichier de depart",memes_octets("build/rob_message.txt", "build/rob_message.out"));

    lancer(cmd_newkeys, &kr, "newkeys cylia crypt");
    lancer(cmd_crypt, &kr, "crypt cylia build/rob_message.txt build/rob_message2.enc");
    verifier("uncrypt avec la mauvaise cle : erreur",lancer(cmd_uncrypt, &kr, "uncrypt tiziri build/rob_message2.enc build/rob_message2.out") != CMD_OK);

    verifier("bin-2b64", lancer(cmd_bin2b64, &kr, "bin-2b64 build/rob_message.txt build/rob_message.b64") == CMD_OK);
    verifier("b64-2bin", lancer(cmd_b642bin, &kr, "b64-2bin build/rob_message.b64 build/rob_message.bin") == CMD_OK);
    verifier("base 64 puis retour : fichier identique", memes_octets("build/rob_message.txt", "build/rob_message.bin"));
    keyring_free(&kr);
}

static void test_boucle_du_shell(void) {
    printf("\n***** La boucle du shell continue apres des erreurs *****\n");
    KeyRing kr;
    keyring_init(&kr);

    char longue[400];
    memset(longue, 'a', 300);
    longue[300] = '\0';

    char entree[600];
    sprintf(entree, "blabla\n\n   \n\t\nnewkeys\nrmkeys\n%s\nnewkeys a crypt\nquit\n", longue);
    ecrire_fichier("build/rob_entree.txt", entree);

    freopen("build/rob_entree.txt", "r", stdin);   // le shell lit le fichier au lieu du clavier
    int r = interpreter_run(&kr);

    verifier("le shell se termine normalement (quit)", r == 0);
    verifier("apres commande inconnue, lignes vides, ligne trop longue et mauvais arguments, 'newkeys a crypt' a marche",
          keyring_find(&kr, "a") != NULL);
    keyring_free(&kr);
}

int main(void) {
    srand(2026);
    test_arguments();
    test_identifiants();
    test_fichiers_introuvables();
    test_type_de_clef();
    test_sauvegarde();
    test_beaucoup_de_cles();
    test_chaine_complete();
    test_boucle_du_shell();  
    return nbEchecs;
}





