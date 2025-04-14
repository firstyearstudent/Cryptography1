#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"

// AES S-box
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Hàm thay thế byte bằng S-box
static void SubBytes(uint8_t *state) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] = sbox[state[i]];
    }
}

// Hàm hoán vị hàng (ShiftRows)
static void ShiftRows(uint8_t *state) {
    uint8_t temp;

    // Row 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Row 2
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Row 3
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

// Hàm nhân ma trận trong trường GF(2^8) (MixColumns)
static void MixColumns(uint8_t *state) {
    // Implement the MixColumns function logic here
    for (int i = 0; i < 4; i++) {
        uint8_t a = state[i * 4];
        uint8_t b = state[i * 4 + 1];
        uint8_t c = state[i * 4 + 2];
        uint8_t d = state[i * 4 + 3];

        state[i * 4] = (uint8_t)(0x02 * a ^ 0x03 * b ^ c ^ d);
        state[i * 4 + 1] = (uint8_t)(a ^ 0x02 * b ^ 0x03 * c ^ d);
        state[i * 4 + 2] = (uint8_t)(a ^ b ^ 0x02 * c ^ 0x03 * d);
        state[i * 4 + 3] = (uint8_t)(0x03 * a ^ b ^ c ^ 0x02 * d);
    }
}

// Hàm thêm khóa vòng (AddRoundKey)
static void AddRoundKey(uint8_t *state, const uint8_t *round_key) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] ^= round_key[i];
    }
}

// Hàm mở rộng khóa (Key Expansion)
static void KeyExpansion(const uint8_t *key, uint8_t *round_keys, uint8_t key_size) {
    (void)key; // Mark the parameter as unused to suppress the warning
    // ... (triển khai hàm mở rộng khóa)
}

// Hàm khởi tạo AES context
void AES_init(AES_Context *ctx, const uint8_t *key, uint8_t key_size) {
    if (key_size != AES_KEY_SIZE_128 && key_size != AES_KEY_SIZE_192 && key_size != AES_KEY_SIZE_256) {
        fprintf(stderr, "Invalid key size: %d bytes\n", key_size);
        exit(EXIT_FAILURE);
    }
    ctx->rounds = (key_size == AES_KEY_SIZE_128) ? 10 : (key_size == AES_KEY_SIZE_192) ? 12 : 14;
    KeyExpansion(key, ctx->round_keys, key_size);
}

void AES_encrypt_block(AES_Context *ctx, const uint8_t *input, uint8_t *output) {
    uint8_t state[AES_BLOCK_SIZE];
    memcpy(state, input, AES_BLOCK_SIZE);

    AddRoundKey(state, ctx->round_keys);

    for (int round = 1; round < ctx->rounds; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, ctx->round_keys + round * AES_BLOCK_SIZE);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, ctx->round_keys + ctx->rounds * AES_BLOCK_SIZE);

    memcpy(output, state, AES_BLOCK_SIZE);
}

void AES_decrypt_block(AES_Context *ctx, const uint8_t *input, uint8_t *output) {
    uint8_t state[AES_BLOCK_SIZE];
    memcpy(state, input, AES_BLOCK_SIZE);

    AddRoundKey(state, ctx->round_keys + ctx->rounds * AES_BLOCK_SIZE);

    for (int round = ctx->rounds - 1; round > 0; round--) {
        ShiftRows(state); // Ngược lại với mã hóa
        SubBytes(state);  // Ngược lại với mã hóa
        AddRoundKey(state, ctx->round_keys + round * AES_BLOCK_SIZE);
        MixColumns(state); // Ngược lại với mã hóa
    }

    ShiftRows(state);
    SubBytes(state);
    AddRoundKey(state, ctx->round_keys);

    memcpy(output, state, AES_BLOCK_SIZE);
}

// Hàm mã hóa dữ liệu với padding
void aes_encrypt(const uint8_t *input, size_t input_length, uint8_t **output, size_t *output_length) {
    AES_Context ctx;
    uint8_t key[AES_KEY_SIZE_256] = {0}; // Khóa ví dụ (thay thế bằng khóa thực tế)
    AES_init(&ctx, key, AES_KEY_SIZE_256);

    *output_length = ((input_length + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    *output = (uint8_t *)malloc(*output_length);
    if (!*output) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < *output_length; i += AES_BLOCK_SIZE) {
        uint8_t block[AES_BLOCK_SIZE] = {0};
        size_t copy_size = (i + AES_BLOCK_SIZE <= input_length) ? AES_BLOCK_SIZE : input_length - i;
        memcpy(block, input + i, copy_size);

        // Apply PKCS#7 padding to the last block
        if (i + AES_BLOCK_SIZE >= *output_length) {
            uint8_t padding_value = AES_BLOCK_SIZE - copy_size;
            memset(block + copy_size, padding_value, padding_value);
        }

        AES_encrypt_block(&ctx, block, *output + i);
    }
}

// Hàm giải mã dữ liệu
void aes_decrypt(const uint8_t *input, size_t input_length, uint8_t **output, size_t *output_length) {
    if (input_length % AES_BLOCK_SIZE != 0) {
        fprintf(stderr, "Invalid input length for AES decryption\n");
        exit(EXIT_FAILURE);
    }

    AES_Context ctx;
    uint8_t key[AES_KEY_SIZE_256] = {0}; // Khóa ví dụ (thay thế bằng khóa thực tế)
    AES_init(&ctx, key, AES_KEY_SIZE_256);

    *output_length = input_length;
    *output = (uint8_t *)malloc(*output_length);
    if (!*output) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < *output_length; i += AES_BLOCK_SIZE) {
        uint8_t block[AES_BLOCK_SIZE] = {0};
        memcpy(block, input + i, AES_BLOCK_SIZE);
        AES_decrypt_block(&ctx, block, *output + i);
    }

    // Remove PKCS#7 padding
    uint8_t padding_value = (*output)[*output_length - 1];
    if (padding_value > 0 && padding_value <= AES_BLOCK_SIZE) {
        for (size_t i = 0; i < padding_value; i++) {
            if ((*output)[*output_length - 1 - i] != padding_value) {
                fprintf(stderr, "Invalid padding detected\n");
                free(*output);
                *output = NULL;
                *output_length = 0;
                return;
            }
        }
        *output_length -= padding_value;
    } else {
        fprintf(stderr, "Invalid padding detected\n");
        free(*output);
        *output = NULL;
        *output_length = 0;
    }
}

// Hàm main để kiểm tra
int main() {
    const char *input_file = "input.txt";
    const char *encrypted_file = "encrypted.txt";
    const char *decrypted_file = "decrypted.txt";

    // Đọc dữ liệu từ file input.txt
    FILE *file = fopen(input_file, "rb");
    if (!file) {
        perror("Failed to open input file");
        return EXIT_FAILURE;
    }
    fseek(file, 0, SEEK_END);
    size_t input_length = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t *input_data = (uint8_t *)malloc(input_length);
    if (!input_data) {
        perror("Memory allocation failed");
        fclose(file);
        return EXIT_FAILURE;
    }
    fread(input_data, 1, input_length, file);
    fclose(file);

    // Mã hóa dữ liệu
    uint8_t *encrypted_data = NULL;
    size_t encrypted_length = 0;
    aes_encrypt(input_data, input_length, &encrypted_data, &encrypted_length);

    // Ghi dữ liệu mã hóa vào file encrypted.txt
    file = fopen(encrypted_file, "wb");
    if (!file) {
        perror("Failed to open encrypted file");
        free(input_data);
        free(encrypted_data);
        return EXIT_FAILURE;
    }
    fwrite(encrypted_data, 1, encrypted_length, file);
    fclose(file);

    // Giải mã dữ liệu
        uint8_t *decrypted_data = NULL;
        size_t decrypted_length = 0;
        aes_decrypt(encrypted_data, encrypted_length, &decrypted_data, &decrypted_length);
        if (decrypted_length > 0) {
            uint8_t padding_value = decrypted_data[decrypted_length - 1]; // Extract padding value
            if (padding_value > 0 && padding_value <= AES_BLOCK_SIZE) {
                int valid_padding = 1;
                for (size_t i = 0; i < padding_value; i++) {
                    if (decrypted_data[decrypted_length - 1 - i] != padding_value) {
                        valid_padding = 0;
                        break;
                    }
                }
                if (valid_padding) {
                    decrypted_length -= padding_value;
                } else {
                    fprintf(stderr, "Invalid padding detected\n");
                    decrypted_length = 0; // Reset length to avoid writing invalid data
                }
            } else {
                fprintf(stderr, "Invalid padding detected\n");
                decrypted_length = 0; // Reset length to avoid writing invalid data
            }
        }
    
    // Ghi dữ liệu giải mã vào file decrypted.txt
    FILE *decrypted_file_ptr = fopen(decrypted_file, "wb");
    if (!decrypted_file_ptr) {
        perror("Failed to open decrypted file");
        free(input_data);
        free(encrypted_data);
        free(decrypted_data);
        return EXIT_FAILURE;
    }
    fwrite(decrypted_data, 1, decrypted_length, decrypted_file_ptr);
    fclose(decrypted_file_ptr);

    // Giải phóng bộ nhớ
    free(input_data);
    free(encrypted_data);
    free(decrypted_data);

    return 0;
}