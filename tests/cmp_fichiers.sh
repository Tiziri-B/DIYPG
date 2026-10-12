#!/bin/sh
# compare chaque fichier dechiffre avec son original
ok=0
for c in utf8 binaire t256 vide; do
    if cmp build/${c}_clair.bin build/${c}_retour.bin; then
        echo "cmp OK $c"
    else
        echo "cmp DIFFERENT $c"; ok=1
    fi
done
exit $ok
