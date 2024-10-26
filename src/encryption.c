// Allows password encryption and decryption.

#include "encryption.h"

void sha1_hash(const char* input, unsigned int inputSize, unsigned char* output, unsigned int* outputSize)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx == NULL){
        printf("[-] - Error creating context\n");
        return;
    }

    const EVP_MD *md = EVP_sha1();
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        printf("[-] - Error initializing digest\n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    if (EVP_DigestUpdate(ctx, input, inputSize) != 1) {
        printf("[-] - Error updating digest\n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    if (EVP_DigestFinal_ex(ctx, output, outputSize) != 1) {
        printf("[-] - Error finalizing digest\n");
    }

    EVP_MD_CTX_free(ctx);
}

// Encrypt the plaintext using the key and iv.
int aes_encrypt(const unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    if (ctx == NULL) {
        printf("[-] - Error creating AES context\n");
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        printf("[-] - Error initializing AES encryption\n");
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        printf("[-] - Error during AES encryption\n");
        return -1;
    }

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        printf("[-] - Error finalizing AES encryption\n");
        return -1;
    }

    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Decrypt the ciphertext using the key and iv.
int aes_decrypt(const unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    if (ctx == NULL) {
        printf("[-] - Error creating AES context\n");
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        printf("[-] - Error initializing AES decryption\n");
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        printf("[-] - Error during AES decryption\n");
        return -1;
    }

    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        printf("[-] - Error finalizing AES decryption\n");
        return -1;
    }

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}