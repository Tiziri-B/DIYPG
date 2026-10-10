#ifndef IO_UTILS_H
#define IO_UTILS_H

#include <stdint.h>
#include <stddef.h>

int read_file(const char *path, uint8_t **buf, size_t *len);
int write_file(const char *path, const uint8_t *buf, size_t len);
void put_u64_le(uint8_t *dst, uint64_t v);
uint64_t get_u64_le(const uint8_t *src);

#endif