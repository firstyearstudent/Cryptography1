#ifndef AES_H
#define AES_H

#include <stdint.h>

// AES block size in bytes
#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

// AES key sizes in bytes
#ifndef AES_KEY_SIZE_128
#define AES_KEY_SIZE_128 16
#endif

#ifndef AES_KEY_SIZE_192
#define AES_KEY_SIZE_192 24
#endif

#ifndef AES_KEY_SIZE_256
#define AES_KEY_SIZE_256 32
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Structure to hold AES context
typedef struct {
    uint8_t round_keys[240]; // Maximum size for 256-bit key
    uint8_t rounds;          // Number of rounds
} AES_Context;

// Function prototypes
void AES_init(AES_Context *ctx, const uint8_t *key, uint8_t key_size);
void AES_encrypt_block(AES_Context *ctx, const uint8_t *input, uint8_t *output);
void AES_decrypt_block(AES_Context *ctx, const uint8_t *input, uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif // AES_H