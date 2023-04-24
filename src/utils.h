#ifndef UTILS_H
#define UTILS_H

#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <blake2.h>

#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <byteswap.h>
#include <dirent.h>

extern bool verbose;

void bin_to_hex(const uint8_t *xs, const size_t len, const bool shorten);

uint8_t hex_to_int(const char x);

bool load_file(const char *file, uint8_t **file_data, size_t *file_size);

#define IV_SIZE (16)
#define TAG_SIZE (16)
#define ENCRYPTION_SIZE(x) (x + IV_SIZE + TAG_SIZE)

uint8_t* encrypt(const uint8_t key[32], const uint8_t *plain_text, size_t *length);
uint8_t* decrypt(const uint8_t key[32], const uint8_t *cipher_text, size_t *length);

#define BLAKE2_HASH_SIZE (16)

bool blake2_hash(uint8_t hash[BLAKE2_HASH_SIZE], const uint8_t *data, const size_t data_len);

int file_chunked(char *file);

#endif
