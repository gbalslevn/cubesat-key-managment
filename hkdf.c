#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>

// https://docs.openssl.org/3.1/man7/EVP_KDF-HKDF/#notes

int main()
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    unsigned char out[16];
    OSSL_PARAM params[5], *p = params;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha256, strlen(SN_sha256));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, "secret", (size_t)6); // The psk
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, "label", (size_t)5); // Info about the protocol can be provided
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "salt", (size_t)4); // The salt
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, out, sizeof(out), params) <= 0)
    {
        printf("Error with EVP_KDF_derive");
    }
    // Cleanup
    EVP_KDF_CTX_free(kctx);

    // Print derived key
    printf("Derived Key: ");
    for (size_t i = 0; i < sizeof(out); i++)
        printf("%02x", out[i]);
    printf("\n");

    return 0;
}

// For at compile og køre det,
// gcc -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -o bin/hkdf hkdf.c -lcrypto && ./hkdf


// For rasperry pi
// gcc -o hkdf hkdf.c -I/home/linuxbrew/.linuxbrew/opt/openssl@3/include -L/home/linuxbrew/.linuxbrew/opt/openssl@3/lib -lcrypto && ./hkdf

