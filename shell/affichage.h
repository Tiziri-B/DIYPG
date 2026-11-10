#ifndef AFFICHAGE_H
#define AFFICHAGE_H

// Fonctions d'affichage avec une couleur par type de message.
// Les couleurs ne sont utilisées que dans un vrai terminal : dans un test ou
// une redirection vers un fichier, le texte reste simple.
// Elles s'utilisent comme printf.

void aff_titre(const char *fmt, ...);    // magenta, sur stdout : titre, bienvenue
void aff_info(const char *fmt, ...);     // jaune, sur stdout   : conseils, aide
void aff_succes(const char *fmt, ...);   // vert, sur stdout    : une commande a réussi
void aff_erreur(const char *fmt, ...);   // rouge, sur stderr   : une commande a échoué

#endif