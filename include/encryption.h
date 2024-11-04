// Allows password encryption and decryption

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define IV_SIZE 16
#define KEY_SIZE 16

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

void sha1_hash(const char* input, unsigned int inputSize, unsigned char* output, unsigned int* outputSize);
int aes_encrypt(const unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext);
int aes_decrypt(const unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext);

#endif //ENCRYPTION_H
