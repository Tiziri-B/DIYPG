# Phase 3 : le shell DIYPG (interpréteur et commandes de chiffrement)

Dans cette phase, j'ai fait la partie shell de DIYPG. Le but est que l'utilisateur puisse se servir du programme avec des commandes, depuis le prompt `diypg>`. On peut gérer les clefs, chiffrer et déchiffrer des fichiers, et convertir des fichiers entre le binaire et le base64.

**Auteure :** Celia

**Mes fichiers :**
- `shell/interpreter.c/.h`
- `shell/cmd_crypto.c/.h`
- `shell/affichage.c/.h`

## 1. Lancer le shell

Le shell est lancé par le `main`, qui appelle `interpreter_run(&kr)` avec l'annuaire de clefs `kr`.

Au démarrage, un message de bienvenue s'affiche. Il change selon l'heure (Bonjour, Bon après-midi, Bonsoir) et il met le nom de l'utilisateur. Il n'apparaît que dans un vrai terminal.

Pour sortir : `quit`, ou `Ctrl+D`.

## 2. Les commandes

| Commande | Ce qu'elle fait |
|---|---|
| `newkeys <keyid> <crypt\|sign>` | génère une paire de clefs |
| `listkeys [<keyid>]` | liste les clefs (ou une seule) |
| `rmkeys <keyid>` | supprime une clef |
| `show <keyid> [pub] [priv]` | affiche une clef |
| `crypt <clair> <chiffre> <keyid>` | chiffre un fichier avec la clef publique (la clef doit être de type `crypt`) |
| `uncrypt <chiffre> <clair> <keyid>` | déchiffre un fichier avec la clef privée (la clef doit être de type `crypt`) |
| `bin-2b64 <fichier_bin> <fichier_b64>` | convertit un fichier en base64 |
| `b64-2bin <fichier_b64> <fichier_bin>` | convertit du base64 en fichier |
| `help` | affiche la liste des commandes |
| `quit` | quitte le shell |

Les quatre premières commandes sont celles de Tiziri (`cmd_keys.c`). Moi, j'ai fait les quatre suivantes (`cmd_crypto.c`). `help` et `quit` sont gérées dans `interpreter.c`.

### Exemple

```text
diypg> crypt message.txt message.enc bob
'message.txt' chiffre dans 'message.enc' avec la clef 'bob'

diypg> uncrypt message.enc message_retrouve.txt bob
'message.enc' dechiffre dans 'message_retrouve.txt' avec la clef 'bob'

diypg> bin-2b64 message.enc message.b64
'message.enc' converti en base64 dans 'message.b64'

diypg> foo
foo : commande inconnue
tape 'help' pour voir les commandes
```

### Messages d'erreur

| Message | Cause |
|---|---|
| `xxx : commande inconnue` | la commande n'existe pas (le shell conseille `help`) |
| `usage : ...` | mauvais nombre de mots |
| `ligne trop longue (254 caracteres maximum)` | la ligne dépasse la taille maximale |
| `crypt : ... id pas trouve` | l'identifiant de clef n'existe pas |
| `crypt : la clef 'x' est de type sign (il faut une clef de type crypt)`
 | la clef n'est pas de type `crypt` (idem pour `uncrypt`) |
| `crypt : modulo N trop petit` | la clef est trop petite pour chiffrer les blocs |
| `uncrypt : valeur hors limites (...)` | mauvaise clef, ou fichier pas chiffré |
| `... lecture ou ecriture du fichier impossible` | fichier introuvable ou impossible à lire ou écrire |

## 3. Comment ça marche

### L'interpréteur (`interpreter.c`)

`interpreter_run` est une boucle. À chaque tour :

1. on affiche le prompt `diypg>` et `fgets` lit la ligne tapée ;
2. si la ligne est trop longue, on affiche une erreur et on jette le reste de la ligne, pour qu'il ne soit pas pris pour une autre commande ;
3. `decouper_ligne` coupe la ligne en mots avec `strtok` (séparateurs : espace, tabulation). Exemple : `crypt bob a.txt a.enc` donne `argv = {"crypt", "bob", "a.txt", "a.enc"}` et `argc = 4` ;
4. ligne vide : on redemande. Premier mot `quit` : on sort ;
5. sinon on cherche le premier mot dans la **table de routage** et on appelle la fonction trouvée avec `(annuaire, argc, argv)`. S'il n'y est pas : « commande inconnue ».

La table de routage est un tableau. Chaque case contient le nom de la commande, sa fonction, sa syntaxe et une description. Comme toutes les fonctions ont la même forme, on peut les mettre dans le même tableau. Pour ajouter une commande, on écrit sa fonction et on ajoute une ligne. La commande `help` parcourt cette table pour afficher la liste, donc elle se met à jour toute seule.

`MAX_ARGS` vaut 5 alors que la commande la plus longue a 4 mots (`show <keyid> pub priv`). La place en plus sert à voir qu'il y a un mot en trop : avec 5 mots, la commande affiche son `usage`.

### Le chiffrement d'un fichier (`rsa_file.c`)

On prend le contenu du fichier et on le découpe en blocs de 4 octets. À la fin, on ajoute toujours 1 à 4 octets de bourrage (padding), tous égaux au nombre d'octets ajoutés. Il y a donc toujours (taille / 4) + 1 blocs, même si la taille est un multiple de 4. On réserve la mémoire pour la taille du fichier chiffré, (taille / 4 + 1) × 8 octets. Puis on chiffre chaque bloc `m` avec `chiffrer_bloc` : `c = m^E mod N`. Chaque `c` est écrit sur 8 octets.

| Fichier | Octets ajoutés | Blocs | Taille chiffrée |
|---|---|---|---|
| « Hello » (5 octets) | `03 03 03` | 2 | 16 octets |
| 8 octets | `04 04 04 04` | 3 | 24 octets |
| vide (0 octet) | `04 04 04 04` | 1 | 8 octets |

Exemple avec « Hello » : `48 65 6C 6C 6F`. Le bourrage donne les blocs `48 65 6C 6C` et `6F 03 03 03`.

**Déchiffrement.** On lit le fichier chiffré par blocs de 8 octets et on déchiffre chaque bloc avec `dechiffrer_bloc` : `m = c^D mod N`, ce qui redonne 4 octets. Après, on regarde le dernier octet `k` (de 1 à 4) et on vérifie que les `k` derniers octets valent tous `k` : `03 03 03` pour 3, `02 02` pour 2, `01` pour 1, `04 04 04 04` pour 4 (un bloc entier). Si c'est bon, on enlève ces `k` octets. Sinon on renvoie une erreur (mauvaise clef ou fichier pas chiffré).

### L'affichage (`affichage.c`)

Chaque type de message a sa couleur : magenta pour les titres, jaune pour les conseils, vert quand ça a marché, rouge pour les erreurs (écrites sur `stderr`). Les couleurs ne s'affichent que dans un vrai terminal (`isatty`). Dans les tests ou avec une redirection, il n'y a pas de codes de couleur.

## 4. Limites

- Les blocs font 4 octets, donc **N doit être plus grand que 2^32**. Sinon `crypt` refuse avec « modulo N trop petit ».
- Le générateur de clefs doit donc produire des N plus grands que 2^32. C'est la partie de Sara, et mes tests utilisent des clefs fixes pour ne pas en dépendre.
- Le fichier est entièrement chargé en mémoire, donc un très gros fichier peut poser problème.
- Les noms de fichiers ne peuvent pas contenir d'espace (la ligne est coupée sur les espaces).
- Une ligne fait au maximum 254 caractères.

## 5. Les tests

```
make build/test_interp && ./build/test_interp
make build/test_cmd_crypto && ./build/test_cmd_crypto
make build/test_file && ./build/test_file
```

| Test | Ce qu'il vérifie |
|---|---|
| `test_interp` | le découpage en mots, la boucle, la ligne trop longue, la commande `help` |
| `test_cmd_crypto` | `crypt` et `uncrypt` (messages variés, mauvaise clef, erreurs), la conversion base64, des scénarios dans le shell |
| `test_file` | le chiffrement par blocs et le bourrage (de 0 à 9 octets, binaire, UTF-8, mauvaise clef) |

Les tests utilisent des clefs fixes plus grandes que 2^32 et pas des clefs générées, pour ne pas dépendre du générateur.