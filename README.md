# diypg
# DIYPG - Do It Yourself Privacy Guard

Projet de L3 Informatique (groupe 15) : un petit GPG en C, avec un RSA simplifié.
Pour l'instant, seule la **phase 1** est rendue.

## Où on en est

| Phase | Contenu | État |
|---|---|---|
| 1 | chiffrement RSA caractère par caractère, tableaux d'octets, fichiers, génération de clefs, base 64 | rendu, base 64 encore en cours |
| 2 à 5 | pas encore commencées | à faire |

## Organisation du dépôt

| Dossier | Contenu |
|---|---|
| `common/` | `io_utils` : lecture/écriture de fichiers en binaire, conversion `uint64_t` en 8 octets et inversement |
| `rsa/` | chiffrement d'un octet (`rsa_chars`), d'un tableau et d'un fichier (`rsa_bytes`), génération des clefs (`rsa_keys`), sauvegarde des clefs (`rsa_keyio`), fonctions fournies (`rsa_tools`, `bezout`) |
| `codec/` | conversion base 64 |
| `tests/` | un programme de test par module (`test_*.c`) |
| `fournis/` | fichiers donnés dans le sujet, gardés tels quels |
| `bc/`, `hash/`, `shell/`, `src/`, `docs/` | réservés aux phases suivantes |

## Compiler et tester

À la racine du projet :

    make          # compile tous les tests dans build/
    make test     # compile et lance tous les tests
    make clean    # supprime build/

Pour ne lancer qu'un test :

    make build/test_bytes
    ./build/test_bytes

Le Makefile compile tous les `.c` de `common/`, `rsa/` et `codec/`, puis les lie avec chaque `tests/test_*.c`.
Les avertissements de `rsa_tools.c` (`%llu`, comparaisons signées) viennent du code fourni, on ne l'a pas modifié.

## Choix techniques

**Un octet chiffré = 8 octets.**
RSA est appliqué à chaque octet du message (valeur de 0 à 255) : `C = M^E mod N`.
Le résultat est un nombre plus grand qu'un octet, donc on l'écrit sur 8 octets en little endian (poids faible en premier).
Un fichier chiffré fait 8 fois la taille du fichier d'origine.

Exemple avec la clef publique (E = 3, N = 11413) :
- `A` = 65, et 65³ mod 11413 = 713 = `0x02C9`
- écrit sur 8 octets : `C9 02 00 00 00 00 00 00`

**Contrainte sur N : 255 < N < 2^32.**
- Si N <= 255, deux octets différents peuvent donner le même chiffré, donc on refuse.
- Si N >= 2^32, `puissance_mod_n` calcule `a * a` dans un `uint64_t` et peut déborder, donc on refuse aussi.

**Fichiers en mode binaire** (`"rb"` et `"wb"`).
Sous Windows, le mode texte modifie les octets `0x0A` et `0x1A`, ce qui abîmerait les fichiers chiffrés.

**Fichier vide.** Il est accepté : le chiffré fait aussi 0 octet.

**Déchiffrement.** La longueur d'un fichier chiffré doit être un multiple de 8, sinon on renvoie `RSA_ERR_RANGE`.

## Fonctions principales

| Fonction | Rôle |
|---|---|
| `chiffrer_char`, `dechiffrer_char` | un octet (voir `rsa_chars.h`) |
| `chiffrer_octets`, `dechiffrer_octets` | un tableau d'octets, la sortie est allouée par la fonction et libérée par l'appelant avec `free` |
| `chiffrer_fichier`, `dechiffrer_fichier` | un fichier entier, de `in` vers `out` |
| `read_file`, `write_file` | lecture et écriture d'un fichier |
| `put_u64_le`, `get_u64_le` | `uint64_t` vers 8 octets et inversement |
| `generateKeys`, `keyCheck`, `printKey` | génération, vérification et affichage des clefs |
| `key_save`, `key_load` | sauvegarde et chargement d'une paire de clefs |

## Codes de retour

| Code | Valeur | Signification |
|---|---|---|
| `RSA_OK` | 0 | tout s'est bien passé |
| `RSA_ERR_ARG` | -1 | pointeur NULL |
| `RSA_ERR_SMALL_N` | -2 | N <= 255 |
| `RSA_ERR_RANGE` | -3 | N trop grand, longueur invalide ou chiffré >= N |
| `RSA_ERR_MEM` | -4 | `malloc` a échoué |
| `RSA_ERR_IO` | -100 | fichier introuvable ou impossible à écrire |

`RSA_ERR_MEM` et `RSA_ERR_IO` sont définis dans `rsa_bytes.h`.

## Tests

`make test` lance les 5 programmes de `tests/`. Pour les octets et les fichiers (`test_bytes.c`), on teste :
- un tableau vide, 1 octet (0, 65, 255) et les 256 valeurs possibles
- un texte en UTF-8 (caractères sur plusieurs octets)
- un fichier binaire contenant `00 FF 1A 0A 0D`
- un fichier vide, un fichier introuvable
- une mauvaise clef (on ne doit jamais retrouver le message d'origine)
- une longueur de chiffré qui n'est pas un multiple de 8

Le script `tests/cmp_fichiers.sh` compare ensuite chaque fichier déchiffré avec l'original avec `cmp` (à lancer après `./build/test_bytes`).

## Limites connues

- Le chiffrement caractère par caractère est faible : le même octet donne toujours le même chiffré (c'est demandé par le sujet pour la phase 1).
- Taille des clefs limitée : N < 2^32, donc on reste avec de petits nombres premiers (`MAX_PRIME` = 10000 par défaut).
- La conversion base 64 n'est pas finie.

## Répartition de la phase 1

| Tâche | Contenu | Membre |
|---|---|---|
| 1 | tests de `rsa_tools.c`, génération et affichage des clefs | Sara Boumessouer |
| 2 | chiffrement caractère par caractère, sauvegarde/chargement des clefs | Tiziri Bouaoud |
| 3 | chiffrement de tableaux et fichiers, `io_utils`, tests unitaires | Cylia Makhlouf |

## Comment travailler

Une branche par tâche (`phase1-tX-...`), jamais de push direct sur `main`, tout passe par une Pull Request.