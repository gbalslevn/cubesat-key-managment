#include <relic.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Test AES-CBC encryption/decryption */
static int test_aes_cbc(void) {
    int code = RLC_ERR;
    uint8_t plaintext[] = "This is a test message for AES-CBC encryption in RELIC!";
    size_t plain_len = strlen((char *)plaintext);
    
    // 256-bit key (32 bytes)
    uint8_t key[32]; 
    uint8_t iv[16]; 
    
    uint8_t ciphertext[plain_len + 16]; // 16 bytes longer due to padding
    uint8_t decrypted[plain_len + 16];
    size_t cipher_len = sizeof(ciphertext);
    size_t decrypted_len = sizeof(decrypted);

    printf("=== Testing RELIC AES-CBC ===\n");
    
    // Generate random key and IV
    rand_bytes(key, sizeof(key));
    rand_bytes(iv, sizeof(iv));
    
    printf("Original message: %s\n", plaintext);
    printf("Message length: %zu\n", plain_len);
    printf("Key: ");
    for (size_t i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    printf("IV: ");
    for (size_t i = 0; i < sizeof(iv); i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");
    
    // Encrypt
    if (bc_aes_cbc_enc(ciphertext, &cipher_len, plaintext, plain_len, key, sizeof(key), iv) != RLC_OK) {
        printf("Encryption failed!\n");
        goto end;
    }
    
    printf("Ciphertext length: %zu\n", cipher_len);
    printf("Ciphertext: ");
    for (size_t i = 0; i < cipher_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    
    // Decrypt
    if (bc_aes_cbc_dec(decrypted, &decrypted_len, ciphertext, cipher_len, key, sizeof(key), iv) != RLC_OK) {
        printf("Decryption failed!\n");
        goto end;
    }
    
    // Null-terminate the decrypted string for printing. If the length of the decrypted message fits within the allocated buffer, it places '\0' right after the message.
    if (decrypted_len < sizeof(decrypted)) {
        decrypted[decrypted_len] = '\0';
    } else {
        // The message fills the entire buffer (or more), prevent overflow by placing a null terminator at the last byte.
        decrypted[sizeof(decrypted)-1] = '\0';
    }
    
    printf("Decrypted length: %zu\n", decrypted_len);
    printf("Decrypted message: %s\n", decrypted);
    
    // Verify
    if (decrypted_len == plain_len && memcmp(plaintext, decrypted, plain_len) == 0) {
        printf("SUCCESS: Decrypted matches original!\n");
        code = RLC_OK;
    } else {
        printf("FAILURE: Decrypted doesn't match original!\n");
        printf("Expected length: %zu, got %zu\n", plain_len, decrypted_len);
    }

end:
    return code;
}

int main(void) {
    // Initialize RELIC library
    if (core_init() != RLC_OK) {
        core_clean();
        return 1;
    }

    // Setup security parameters
    if (pc_param_set_any() != RLC_OK) {
        core_clean();
        return 1;
    }

    // Test AES-CBC
    if (test_aes_cbc() != RLC_OK) {
        printf("AES-CBC test failed!\n");
        rand_clean();
        core_clean();
        return 1;
    }

    printf("AES-CBC test completed successfully!\n");
    rand_clean();
    core_clean();
    return 0;
}

// gcc -o aes aes.c -I ../../relic-0.7.0/include -I../relic-target/include ../relic-target/lib/librelic_s.a && ./aes