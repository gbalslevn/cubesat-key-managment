#ifndef IBBE
#define IBBE

#include <stdint.h>

/* System parameters */
typedef struct {
    bn_t gamma;
    bn_t p;
    g1_t g;
    g2_t h;
    gt_t v;
    g2_t *h_gamma;
    int max_users;
    uint8_t *(*H)(const char *id, const bn_t p);
} ibbe_params_t;

/* Private key */
typedef struct {
    g1_t sk;
} ibbe_prv_t;

/* Ciphertext header */
typedef struct {
    g1_t C1;
    g2_t C2;
} ibbe_hdr_t;

/* Full ciphertext */
typedef struct {
    ibbe_hdr_t hdr;
    char **ids;
    int num_ids;
    uint8_t *ct;
    size_t ct_len;
} ibbe_ct_t;

int ibbe_setup(ibbe_params_t *params, int lambda, int m);
int ibbe_extract(ibbe_prv_t *prv, const char *id, const ibbe_params_t *params);
int ibbe_encrypt(ibbe_ct_t *ct, const uint8_t *msg, size_t msg_len, 
                char **ids, int num_ids, const ibbe_params_t *params);
int ibbe_decrypt(uint8_t *out, size_t *out_len, const ibbe_ct_t *ct, 
                const ibbe_prv_t *prv, const char *id, 
                const ibbe_params_t *params);

#endif 