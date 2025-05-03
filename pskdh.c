#include <openssl/evp.h>
#include <openssl/ec.h>
#include <stdio.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>

// https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman

static int KEYSIZE = 16;

void handleErrors() {
    printf("There was an error.");
}

EVP_PKEY *get_peerkey(EVP_PKEY *key)
{
    // Normally, you would receive this from your communication channel.
    // Here, we'll just generate a second keypair for demonstration purposes.
    EVP_PKEY *peerkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);

    if (!ctx)
        handleErrors();

    if (EVP_PKEY_keygen_init(ctx) != 1)
        handleErrors();

    if (EVP_PKEY_keygen(ctx, &peerkey) != 1)
        handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return peerkey;  // This should ideally be received from the real peer
}



unsigned char *ecdh(size_t *secret_len)
{
    EVP_PKEY_CTX *pctx, *kctx;
    EVP_PKEY_CTX *ctx;
    unsigned char *secret;
    EVP_PKEY *pkey = NULL, *peerkey, *params = NULL;
    /* NB: assumes pkey, peerkey have been already set up */

    /* Create the context for parameter generation */
    if (NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
        handleErrors();

    /* Initialise the parameter generation */
    if (1 != EVP_PKEY_paramgen_init(pctx))
        handleErrors();

    /* We're going to use the ANSI X9.62 Prime 256v1 curve */
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1))
        handleErrors();

    /* Create the parameter object params */
    if (!EVP_PKEY_paramgen(pctx, &params))
        handleErrors();

    /* Create the context for the key generation */
    if (NULL == (kctx = EVP_PKEY_CTX_new(params, NULL)))
        handleErrors();

    /* Generate the key */
    if (1 != EVP_PKEY_keygen_init(kctx))
        handleErrors();
    if (1 != EVP_PKEY_keygen(kctx, &pkey))
        handleErrors();

    /* Get the peer's public key, and provide the peer with our public key -
     * how this is done will be specific to your circumstances */
    peerkey = get_peerkey(pkey);

    /* Create the context for the shared secret derivation */
    if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL)))
        handleErrors();

    /* Initialise */
    if (1 != EVP_PKEY_derive_init(ctx))
        handleErrors();

    /* Provide the peer public key */
    if (1 != EVP_PKEY_derive_set_peer(ctx, peerkey))
        handleErrors();

    /* Determine buffer length for shared secret */
    if (1 != EVP_PKEY_derive(ctx, NULL, secret_len))
        handleErrors();

    /* Create the buffer */
    if (NULL == (secret = OPENSSL_malloc(*secret_len)))
        handleErrors();

    /* Derive the shared secret */
    if (1 != (EVP_PKEY_derive(ctx, secret, secret_len)))
        handleErrors();

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);

    /* Never use a derived secret directly. Typically it is passed
     * through some hash function to produce a key */
    return secret;
}

unsigned char *hkdf(unsigned char *secret) {
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    unsigned char *out = malloc(KEYSIZE); // Length of the output key
    OSSL_PARAM params[5], *p = params;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha256, strlen(SN_sha256));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, secret, (size_t)6); // The psk
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, "label", (size_t)5); // Info about the protocol can be provided
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "salt", (size_t)4); // The salt
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, out, KEYSIZE, params) <= 0)
    {
        printf("Error with EVP_KDF_derive");
    }
    // Cleanup
    EVP_KDF_CTX_free(kctx);

    return out;
}

void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void psk_dh() {
    size_t secret_len = 32; // For a reccomended size of 256 bits
    unsigned char *Z = ecdh(&secret_len);
    // print_hex("Z", Z, secret_len);
    
    unsigned char PSK[] = "mysecurepsk"; 
    size_t psk_len = strlen((char *)PSK);

    size_t premaster_len = 2 + secret_len + 2 + psk_len; // Memory allocation, 2 for size of secret_len and then the secret_len itself. Same for psk_len.
    unsigned char *premaster_secret = malloc(premaster_len);

    unsigned char *ptr = premaster_secret;

    // Store length(Z) as 2 bytes (big-endian)
    ptr[0] = (secret_len >> 8) & 0xFF;
    ptr[1] = secret_len & 0xFF;
    ptr += 2;

    // Copy Z
    memcpy(ptr, Z, secret_len);
    ptr += secret_len;

    // Store length(PSK) as 2 bytes (big-endian)
    ptr[0] = (psk_len >> 8) & 0xFF;
    ptr[1] = psk_len & 0xFF;
    ptr += 2;

    // Copy PSK
    memcpy(ptr, PSK, psk_len);

    // print_hex("Premaster secret", premaster_secret, premaster_len);
    size_t master_len = KEYSIZE;
    unsigned char *master_secret = hkdf(premaster_secret);
    // print_hex("Final key", master_secret, master_len);
    
    // Cleanup
    free(Z);
    free(premaster_secret);
    free(master_secret);
}

// int main(int argc, char const *argv[])
// {
//     psk_dh();
//     return 0;
// }

// gcc -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -o pskdh pskdh.c -lcrypto && ./pskdh