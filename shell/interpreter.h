#ifndef INTERPRETER_H
#define INTERPRETER_H
#include "keyring.h"
#define MAX_ARGS 5 //pour detecter si cest plus grand que 4 mots
#define LIGNE_MAX 256 //taille max dune ligne

int decouper_ligne(char *ligne, char **argv, int max);
int interpreter_run(KeyRing *kr);
#endif