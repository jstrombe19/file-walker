#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>

#include "utils.h"

#define CHECK_FREE(ptr) do {if (ptr) free(ptr); ptr = NULL;} while(0)

void bin_to_hex(const uint8_t *xs, const size_t len, const bool shorten)
{
    if (shorten && len > 500) {
        for (size_t i = 0; i < 100; i++)
            fprintf(stdout, "%02X ", xs[i]);
        fprintf(stdout, "\n.......\n");
        for (size_t i = len - 100; i < len; i++)
            fprintf(stdout, "%02X ", xs[i]);
    } else {
        for (size_t i = 0; i < len; i++)
            fprintf(stdout, "%02X ", xs[i]);
    }
    fprintf(stdout, "\n");
}

uint8_t hex_to_int(const char x)
{
    if (x >= '0' && x <= '9')
        return x - '0';
    if (x >= 'A' && x <= 'F')
        return x - 'A' + 10;
    if (x >= 'a' && x <= 'f')
        return x - 'a' + 10;

    fprintf(stdout, "Failed conversion from hex character to integer\n");
    exit(EXIT_FAILURE);
}

bool load_file(const char *file, uint8_t **file_data, size_t *file_size)
{
    int fd = open(file, O_RDONLY);
    if (fd == -1) {
        printf("%s : open failed for file %s", __func__, file);
        return false;
    }
    struct stat f_st;
    fstat(fd, &f_st);
    int bytes_read;

    *file_data = malloc(f_st.st_size);
    if (!*file_data) {
        printf("%s | malloc failed for file %s", __func__, file);
        return false;
    }
    if ((bytes_read = read(fd, *file_data, f_st.st_size)) != f_st.st_size) {
        printf("%s | read failed for file %s", __func__, file);
        return false;
    }

    close(fd);

    printf("%s | f_st.st_size: %ld || bytes_read: %d\n", __func__, f_st.st_size, bytes_read);

    *file_size = f_st.st_size;
    return true;
}

// assumes no padding
// uint8_t* encrypt(const uint8_t key[32], const uint8_t *plain_text, size_t *length)
// {
//     uint8_t *iv_ptr;
//     uint8_t *tag_ptr;
//     uint8_t *cipher_text;
//     uint8_t *ct_ptr;
//     size_t pt_len = *length;
//     size_t cipher_size = ENCRYPTION_SIZE(pt_len);
//     int len;


//     cipher_text = calloc(1, cipher_size);
//     if (!cipher_text) {
//         printf("calloc");
//         return NULL;
//     }
//     ct_ptr = cipher_text + IV_SIZE;
//     iv_ptr = cipher_text;
//     tag_ptr = cipher_text + IV_SIZE + pt_len;
//     EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
//     if (RAND_bytes(iv_ptr, IV_SIZE) != 1) {
//         fprintf(stdout, "Encription IV init failed");
//         //goto cleanup;
//         EVP_CIPHER_CTX_free(ctx);
//     }

//     //EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
//     if (ctx == NULL) {
//         fprintf(stdout, "Failed to create cipher context\n");
//         //goto free_ct;
//         CHECK_FREE(cipher_text);
//         return NULL;
//     }
//     // set cipher type
//     if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
//         fprintf(stdout, "Encryption init failed\n");
//         //goto cleanup;
//         EVP_CIPHER_CTX_free(ctx);
//     }
//     // set iv length
//     if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) {
//         fprintf(stdout, "Encryption set iv len failed\n");
//         //goto cleanup;
//         EVP_CIPHER_CTX_free(ctx);
//     }
//     // initialize key and iv
//     if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv_ptr) != 1) {
//         fprintf(stdout, "Encryption init key and iv failed\n");
//         //goto cleanup;
//         EVP_CIPHER_CTX_free(ctx);
//     }
//     // // specify the AAD
//     // if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1)
//     //     fprintf(stdout, "Encryption init AAD failed");
//     // encrypt the plain text
//     if (EVP_EncryptUpdate(ctx, ct_ptr, &len, plain_text, pt_len) != 1) {
//         fprintf(stdout, "Encryption cipher update failed\n");
//         //goto cleanup;
//         EVP_CIPHER_CTX_free(ctx);
//     }
//     // finalize, does this do anything for GCM?
//     if (EVP_EncryptFinal_ex(ctx, cipher_text, &len) != 1) {
//         fprintf(stdout, "Encryption cipher final failed\n");
//         //goto cleanup;
//         EVP_CIPHER_CTX_free(ctx);
//     }
//     // get tag
//     if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag_ptr) != 1) {
//         fprintf(stdout, "Encryption get tag failed\n");
//         //goto cleanup;
//         EVP_CIPHER_CTX_free(ctx);
//     }
//     EVP_CIPHER_CTX_free(ctx);

//     if (verbose) {
//         fprintf(stdout, "IV:  ");
//         bin_to_hex(iv_ptr, IV_SIZE, 0);
//         fprintf(stdout, "TAG: ");
//         bin_to_hex(tag_ptr, TAG_SIZE, 0);
//         fprintf(stdout, "Pre encryption:\n");
//         bin_to_hex(plain_text, pt_len, 1);
//         fprintf(stdout, "Post encryption:\n");
//         bin_to_hex(cipher_text, cipher_size, 1);
//     }

//     *length = cipher_size;
//     return cipher_text;

// //cleanup:
// //    EVP_CIPHER_CTX_free(ctx);
// //free_ct:
// //    free(cipher_text);
// //    return NULL;
// }

// uint8_t* decrypt(const uint8_t key[32], const uint8_t *cipher_text, size_t *length)
// {
//     int len;
//     const uint8_t *iv_ptr = cipher_text;
//     const uint8_t *tag_ptr = cipher_text + *length - TAG_SIZE;
//     const uint8_t *ct_ptr = cipher_text + IV_SIZE;
//     size_t   pt_len = *length - IV_SIZE - TAG_SIZE;
//     uint8_t *plain_text = calloc(1, pt_len);
//     if (!plain_text) {
//         printf("calloc");
//         return NULL;
//     }

//     EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
//     if (ctx == NULL) {
//         fprintf(stdout, "Failed to create cipher context\n");
//         goto free_pt;
//     }
//     // set cipher type
//     if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
//         fprintf(stdout, "Decryption init failed\n");
//         goto cleanup;
//     }
//     // set iv length
//     if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) {
//         fprintf(stdout, "Decryption set iv len failed\n");
//         goto cleanup;
//     }
//     // initialize key and iv
//     if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv_ptr) != 1) {
//         fprintf(stdout, "Decryption init key and iv failed\n");
//         goto cleanup;
//     }
//     // encrypt the plain text
//     if (EVP_DecryptUpdate(ctx, plain_text, &len, ct_ptr, pt_len) != 1) {
//         fprintf(stdout, "Decryption cipher update failed\n");
//         goto cleanup;
//     }
//     // set the tag
//     if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (uint8_t*)tag_ptr) != 1) {
//         fprintf(stdout, "Decryption set tag failed\n");
//         goto cleanup;
//     }
//     // finalize, does this do anything for GCM?
//     if (EVP_DecryptFinal_ex(ctx, plain_text, &len) != 1) {
//         fprintf(stdout, "Decryption cipher final failed\n");
//         goto cleanup;
//     }
//     EVP_CIPHER_CTX_free(ctx);

//     if (verbose) {
//         fprintf(stdout, "IV:  ");
//         bin_to_hex(iv_ptr, IV_SIZE, 0);
//         fprintf(stdout, "TAG: ");
//         bin_to_hex(tag_ptr, TAG_SIZE, 0);
//         fprintf(stdout, "Pre decryption:\n");
//         bin_to_hex(cipher_text, *length, 1);
//         fprintf(stdout, "Post decryption:\n");
//         bin_to_hex(plain_text, pt_len, 1);
//     }

//     *length = pt_len;
//     return plain_text;

// cleanup:
//     EVP_CIPHER_CTX_free(ctx);
// free_pt:
//     CHECK_FREE(plain_text);
//     return NULL;
// }

// #define BLAKE2_HASH_SIZE (16)

// bool blake2_hash(uint8_t hash[BLAKE2_HASH_SIZE], const uint8_t *data, const size_t data_len)
// {
//     if (blake2s(hash, data, NULL, BLAKE2_HASH_SIZE, data_len, 0) < 0) {
//         fprintf(stdout, "Blake2s hash failed\n");
//         return false;
//     }
//     if (verbose) {
//         fprintf(stdout, "Blake2s: ");
//         bin_to_hex(hash, BLAKE2_HASH_SIZE, 0);
//     }
//     return true;
// }

int file_chunked(char *file)
{
    int result;
    char chunked[] = "_chunked";

    result = (strstr(file, chunked) != NULL) ? 1 : 0;
    return result;
}