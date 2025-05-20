#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

#define AES_KEYLEN 256  // AES-256
#define AES_BLOCK_SIZE 16

int aes_256_cbc_encrypt(unsigned char *plaintext, int plaintext_len,
            unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_256_cbc_decrypt(unsigned char *ciphertext, int ciphertext_len,
            unsigned char *key, unsigned char *iv,
            unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;
    int result;

    // if(!(ctx = EVP_CIPHER_CTX_new())) {
    //     result = 0;
    // }

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// int main() {
//     unsigned char key[32];  // 256-bit key
//     unsigned char iv[AES_BLOCK_SIZE];  // 128-bit IV

//     // Generate random key and IV (you can also set them manually)
//     RAND_bytes(key, sizeof(key));
//     RAND_bytes(iv, sizeof(iv));

//     // Message to encrypt
//     unsigned char *plaintext = (unsigned char *)"This is a secret message.";
//     unsigned char ciphertext[128];
//     unsigned char decryptedtext[128];

//     int ciphertext_len = aes_256_cbc_encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);
//     int decryptedtext_len = aes_256_cbc_decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

//     printf("Original : %s\n", plaintext);
//     printf("Encrypted: ");
//     for (int i = 0; i < ciphertext_len; i++)
//         printf("%02x", ciphertext[i]);
//     printf("\nDecrypted: %s\n", decryptedtext);

//     return 0;
// }

// gcc -o bin/aes aes.c -lcrypto && bin/aes