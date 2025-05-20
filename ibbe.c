#include <relic.h>
#include "relic_test.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"

/**
 * The Delerablée IBBE scheme based on https://www.iacr.org/archive/asiacrypt2007/48330198/48330198.pdf
 */

/* System parameters */
typedef struct {
    bn_t gamma;         // Master secret key γ
    bn_t p;             // prime 
    g1_t g;             // Generator of G1
    g2_t h;             // Generator of G2
    gt_t v;             // e(g,h)
    g2_t *h_gamma;      // Array [h^γ, h^{γ^2}, ..., h^{γ^m}]
    int max_users;      // Maximum number of recipients (m)
    uint8_t *(*H)(const char *id, const bn_t p); // Hash function H: {0,1}* → Zp*
} ibbe_params_t;

/* Private key */
typedef struct {
    g1_t sk;            // g^{1/(γ+H(ID))}
} ibbe_prv_t;

/* Ciphertext header */
typedef struct {
    g1_t C1;            // w^{-k} = g^{-kγ}
    g2_t C2;            // h^{k·∏(γ+H(IDi))}
} ibbe_hdr_t;

/* Full ciphertext */
typedef struct {
    ibbe_hdr_t hdr;
    char **ids;         // Array of recipient identities
    int num_ids;        // Number of recipients (s ≤ m)
    uint8_t *ct;        // Encrypted message
    size_t ct_len;
} ibbe_ct_t;

uint8_t static_iv_value[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F
};
uint8_t *static_iv = (uint8_t *)static_iv_value;

void print_char(const u_int8_t *msg, size_t msg_len) {
    for (size_t i = 0; i < msg_len; i++) {
        printf("%c", msg[i]);
    }
    printf("\n");
}
void print_hex(const u_int8_t *msg, size_t msg_len) {
    for (size_t i = 0; i < msg_len; i++) {
        printf("%02x", msg[i]);
    }
    printf("\n");
}

/* Hash function H: {0,1}* → Zp* */
uint8_t *hash_to_zp(const char *id, const bn_t p) {
    uint8_t *hash = malloc(RLC_MD_LEN);
    uint8_t digest[RLC_MD_LEN]; // Enough for SHA-256
    
    // Hash the ID using SHA-256
    md_map_sh256(digest, (uint8_t *)id, strlen(id));

    // Convert digest to a bn_t to do mod p
    bn_t h;
    bn_null(h);
    bn_new(h);
    bn_read_bin(h, digest, RLC_MD_LEN);
    bn_mod(h, h, p);
    
    // Write back to bytes
    bn_write_bin(hash, RLC_FP_BYTES, h);
    
    // Clean up
    bn_free(h);
    
    return hash;
}

/* Setup the system */
int ibbe_setup(ibbe_params_t *params, int lambda, int m) {
    int result = RLC_OK;
    
    bn_null(params->gamma);
    bn_null(params->p);
    g1_null(params->g);
    g2_null(params->h);
    gt_null(params->v);
    params->h_gamma = NULL;
    
    RLC_TRY {
        bn_new(params->gamma);
        bn_new(params->p);
        g1_new(params->g);
        g2_new(params->h);
        gt_new(params->v);
        
        // Get group order 
        pc_get_ord(params->p);
        if (!bn_is_prime(params->p)) {
            printf("Error: Group order is not prime!\n");
            result = RLC_ERR;
            RLC_THROW(ERR_CAUGHT);
        }

        // Generate random γ in Zp*
        bn_rand(params->gamma, RLC_POS, lambda);
        bn_mod(params->gamma, params->gamma, params->p);
        
        // Generate generators
        g1_rand(params->g);
        g2_rand(params->h);
        
        // Precompute v = e(g,h)
        pc_map(params->v, params->g, params->h);
        
        // Precompute h^{γ^i} for i=1..m
        params->h_gamma = malloc((m+1) * sizeof(g2_t));
        for (int i = 0; i <= m; i++) {
            g2_null(params->h_gamma[i]);
            g2_new(params->h_gamma[i]);
            if (i == 0) {
                g2_set_infty(params->h_gamma[i]);
            } else if (i == 1) {
                g2_mul(params->h_gamma[i], params->h, params->gamma);
            } else {
                g2_mul(params->h_gamma[i], params->h_gamma[i-1], params->gamma);
            }
        }
        
        params->max_users = m;
        
        params->H = &hash_to_zp; 
    } RLC_CATCH_ANY {
        result = RLC_ERR;
    }
    
    return result;
}

/* Extract private key for an identity */
int ibbe_extract(ibbe_prv_t *prv, const char *id, const ibbe_params_t *params) {
    int result = RLC_OK;
    bn_t h_id, gamma_plus_h, inv;
    
    bn_null(h_id);
    bn_null(gamma_plus_h);
    bn_null(inv);
    g1_null(prv->sk);
    
    RLC_TRY {
        bn_new(h_id);
        bn_new(gamma_plus_h);
        bn_new(inv);
        g1_new(prv->sk);
        
        // Compute H(ID)
        uint8_t *hash = params->H(id, params->p);
        bn_read_bin(h_id, hash, RLC_FP_BYTES);
        free(hash);
        
        // Compute γ + H(ID)
        bn_add(gamma_plus_h, params->gamma, h_id);
        
        // Compute 1/(γ + H(ID)) mod p
        bn_mod_inv(inv, gamma_plus_h, params->p);
        
        // Compute g^{1/(γ+H(ID))}
        g1_mul(prv->sk, params->g, inv);
    } RLC_CATCH_ANY {
        result = RLC_ERR;
    }
    
    bn_free(h_id);
    bn_free(gamma_plus_h);
    bn_free(inv);
    return result;
}

/* Encrypt for a set of identities */
int ibbe_encrypt(ibbe_ct_t *ct, uint8_t *msg, size_t msg_len, 
                char **ids, int num_ids, const ibbe_params_t *params) {
    int result = RLC_OK;
    bn_t k, product, h_id, temp;
    g1_t w;
    gt_t K;
    
    bn_null(k);
    bn_null(product);
    bn_null(h_id);
    bn_null(temp);
    g1_null(w);
    g1_null(ct->hdr.C1);
    g2_null(ct->hdr.C2);
    gt_null(K);

    RLC_TRY {
        bn_new(k);
        bn_new(product);
        bn_new(h_id);
        bn_new(temp);
        g1_new(w);
        g1_new(ct->hdr.C1);
        g2_new(ct->hdr.C2);
        gt_new(K);
        
        // Generate random k
        bn_rand(k, RLC_POS, RLC_BN_BITS);
        
        // Compute w = g^γ
        g1_mul(w, params->g, params->gamma);
        
        // Compute C1 = w^{-k} = g^{-kγ}
        g1_mul(ct->hdr.C1, w, k);
        g1_neg(ct->hdr.C1, ct->hdr.C1);
        
        // Compute product = ∏(γ + H(IDi))
        bn_set_dig(product, 1);
        for (int i = 0; i < num_ids; i++) {
            uint8_t *hash = params->H(ids[i], params->p);
            bn_read_bin(h_id, hash, RLC_FP_BYTES);
            free(hash);
         
            bn_add(temp, params->gamma, h_id);
            bn_mul(product, product, temp);
        }
        
        // Compute C2 = h^{k·product}
        bn_mul(temp, k, product);
        g2_mul(ct->hdr.C2, params->h, temp);

        // Compute K = v^k = e(g,h)^k
        gt_exp(K, params->v, k);
        
        int gt_len = gt_size_bin(K, 1);
        uint8_t key_bytes[gt_len];

        // Derive symmetric key
        gt_write_bin(key_bytes, gt_len, K, 1);
        uint8_t aes_key[32];
        memcpy(aes_key, key_bytes, 32); // Just takes first 32 bytes, should use KDF, like md_kdf(key, 2 * size, _x, l);

        // printf("Derived AES key: ");
        // print_hex(aes_key, 32);
        
        // Store identities
        ct->ids = malloc(num_ids * sizeof(char *));
        // printf("Identities which should be able to decrypt: \n");
        for (int i = 0; i < num_ids; i++) {
            // printf("%s\n", ids[i]);
            ct->ids[i] = strdup(ids[i]);
        }
        ct->num_ids = num_ids;
        
        ct->ct_len = msg_len + RLC_MD_LEN; 
        ct->ct = malloc(ct->ct_len);
        if (ct->ct == NULL) {
            result = RLC_ERR;
            RLC_THROW(ERR_CAUGHT);
        }
        aes_256_cbc_encrypt(msg, msg_len, aes_key, static_iv, ct->ct);
    } RLC_CATCH_ANY {
        result = RLC_ERR;
    }
    
    bn_free(k);
    bn_free(product);
    bn_free(h_id);
    bn_free(temp);
    g1_free(w);
    gt_free(K);
    return result;
}

/* Decrypt the message */
int ibbe_decrypt(uint8_t *out, size_t *out_len, const ibbe_ct_t *ct, 
                const ibbe_prv_t *prv, const char *id, 
                const ibbe_params_t *params) {
    int result = RLC_OK;
    bn_t *h_ids = NULL, product, denominator, temp, inv;
    g2_t h_pi, h_temp;
    gt_t K_prime, numerator, denominator_gt;
    int recipient_idx = -1;
    int gt_len;

    // Find the recipient in the set
    for (int i = 0; i < ct->num_ids; i++) {
        if (strcmp(id, ct->ids[i]) == 0) {
            recipient_idx = i;
            break;
        }
    }
    if (recipient_idx == -1) {
        printf("id '%s' is not on the list of receivers\n", id);
        return RLC_ERR;  
    } 
    
    RLC_TRY {
        bn_new(product);
        bn_new(denominator);
        bn_new(temp);
        bn_new(inv);
        g2_new(h_pi);
        g2_new(h_temp);
        gt_new(K_prime);
        gt_new(numerator);
        gt_new(denominator_gt);

         // Allocate memory for H(IDj) values
        h_ids = malloc(ct->num_ids * sizeof(bn_t));
        for (int i = 0; i < ct->num_ids; i++) {
            bn_null(h_ids[i]);
            bn_new(h_ids[i]);
            uint8_t *hash = params->H(ct->ids[i], params->p);
            bn_read_bin(h_ids[i], hash, RLC_FP_BYTES);
            free(hash);
        }
        
        // Compute denominator = ∏_{j≠i} H(IDj)
        bn_set_dig(denominator, 1);
        for (int j = 0; j < ct->num_ids; j++) {
            if (j != recipient_idx) {
                bn_mul(denominator, denominator, h_ids[j]);
            }
        }
        
        // Compute pi_S(γ) = (∏_{j≠i}(γ + H(IDj)) - ∏_{j≠i}H(IDj)) / γ
        // First compute ∏_{j≠i}(γ + H(IDj))
        bn_set_dig(product, 1);
        for (int j = 0; j < ct->num_ids; j++) {
            if (j != recipient_idx) {
                bn_add(temp, params->gamma, h_ids[j]);
                bn_mul(product, product, temp);
            }
        }
        
        // Then compute (product - denominator)/γ
        bn_sub(temp, product, denominator);
        
        // Get group order and compute 1/γ mod p
        // Compute pi_S(γ) = (product - denominator)/γ
        bn_mod_inv(inv, params->gamma, params->p);
        bn_mul(temp, temp, inv);
        bn_mod(temp, temp, params->p);
        
        // Compute h^{pi_S(γ)}
        g2_mul(h_pi, params->h, temp);
        
        // Compute e(C1, h^{pi_S(γ)})
        pc_map(numerator, ct->hdr.C1, h_pi);
        
        // Compute e(sk_IDi, C2)
        pc_map(denominator_gt, prv->sk, ct->hdr.C2);
        
        // Compute K' = (numerator * denominator_gt)^{1/denominator}
        gt_mul(K_prime, numerator, denominator_gt);
        
        // Compute 1/denominator mod p
        bn_mod_inv(inv, denominator, params->p);
        
        // Compute K = K'^{inv}
        gt_exp(K_prime, K_prime, inv);
        
        // Derive symmetric key
        gt_len = gt_size_bin(K_prime, 1);
        uint8_t key_bytes[gt_len];
        gt_write_bin(key_bytes, gt_len, K_prime, 1);
        uint8_t aes_key[32];
        memcpy(aes_key, key_bytes, 32); // Just takes first 32 bytes, should use KDF, like md_kdf(key, 2 * size, _x, l);

        // printf("Derived AES key: ");
        // print_hex(aes_key, 32);
        
        // Decrypt message
        // use a constant IV for testing
        aes_256_cbc_decrypt(ct->ct, ct->ct_len, aes_key, static_iv, out);
    } RLC_CATCH_ANY {
        result = RLC_ERR;
    }

end:  
    // Cleanup
    if (h_ids) {
        for (int i = 0; i < ct->num_ids; i++) {
            bn_free(h_ids[i]);
        }
        free(h_ids);
    }
    bn_free(product);
    bn_free(denominator);
    bn_free(temp);
    bn_free(inv);
    g2_free(h_pi);
    g2_free(h_temp);
    gt_free(K_prime);
    gt_free(numerator);
    gt_free(denominator_gt);
    
    return result;
}

// int main() {
//     // Initialize RELIC library
//     if (core_init() != RLC_OK) {
//         core_clean();
//         return 1;
//     }

//     // Setup pairing parameters
//     if (pc_param_set_any() != RLC_OK) {
//         core_clean();
//         return 1;
//     }

//     if (ibbe_test() != RLC_OK) {
//         printf("IBBE test failed!\n");
//         core_clean();
//         return 1;
//     }

//     printf("IBBE test passed successfully!\n");
//     // Clean up RELIC
//     core_clean();
//     return 0;
// }

// gcc -o bin/ibbe ibbe.c aes.c -I ../relic-0.7.0/include -I relic-target/include relic-target/lib/librelic_s.a && ./ibbe

// For linux
// gcc -o ibbe ibbe.c aes.c -I ../relic/include -I ../relic-target/include ../relic-target/lib/librelic_s.a -I/home/linuxbrew/.linuxbrew/opt/openssl@3/include -L/home/linuxbrew/.linuxbrew/opt/openssl@3/lib -lcrypto && ./ibbe

// For at ændre indstillinger, 'ccmake target-relic'. Ændre indtillinger gem og generate (g) og derefter 'make'.

