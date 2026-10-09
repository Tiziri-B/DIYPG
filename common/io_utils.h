#ifndef IO_UTILS_H
#define IO_UTILS_H
#include <stddef.h>
#include <stdint.h>

/* Lit un fichier entier en memoire. L'appelant doit faire free(*buf). */
int read_file(const char *path, uint8_t **buf, size_t *len);

/* Ecrit len octets dans un fichier (mode binaire). */
int write_file(const char *path, const uint8_t *buf, size_t len);

/* Ecrit / lit un uint64 sur 8 octets, petit-boutiste. */
void     put_u64_le(uint8_t *dst, uint64_t v);
uint64_t get_u64_le(const uint8_t *src);
#endif
