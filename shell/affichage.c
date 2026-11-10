#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include "affichage.h"

#define MAGENTA "\033[1;35m"
#define JAUNE   "\033[1;33m"
#define VERT    "\033[1;32m"
#define ROUGE   "\033[1;31m"
#define FIN     "\033[0m"

// écrit le texte formaté sur le flux, avec la couleur si c'est un terminal
static void ecrire(FILE *flux, const char *couleur, const char *fmt, va_list args) {
    int en_couleur = isatty(fileno(flux));
    if (en_couleur) fputs(couleur, flux);
    vfprintf(flux, fmt, args);
    if (en_couleur) fputs(FIN, flux);
}

void aff_titre(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    ecrire(stdout, MAGENTA, fmt, args);
    va_end(args);
}

void aff_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    ecrire(stdout, JAUNE, fmt, args);
    va_end(args);
}

void aff_succes(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    ecrire(stdout, VERT, fmt, args);
    va_end(args);
}

void aff_erreur(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    ecrire(stderr, ROUGE, fmt, args);
    va_end(args);
}