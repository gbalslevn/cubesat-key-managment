/**
 * Benchmarking using the linux tool perf
 */

#include <stdio.h>
#include "relic.h"
#include "relic_test.h"
#include "pskdh.h"
#include "ibbe.h"
#include <linux/perf_event.h>
#include <unistd.h>

static long perf_event_open(struct perf_event_attr *pe, pid_t pid,
                           int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, pe, pid, cpu, group_fd, flags);
}

void measure_cycles(const char *name, void (*func)()) {
    struct perf_event_attr pe = {0};
    long long count;
    int fd;

    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    fd = perf_event_open(&pe, 0, -1, -1, 0);
    if (fd == -1) {
        perror("perf_event_open failed");
        return;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    // Run the function
    func();

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    read(fd, &count, sizeof(count));

    printf("%s: %lld CPU cycles\n", name, count);
    close(fd);
}

void hkdf_test()
{
    unsigned char premaster_secret[] = "secretkey";
    unsigned char *master_secret = hkdf(premaster_secret);
}

void pskdh_test()
{
    const char *psk = "asecretpsk";
    const char *anotherpsk = "anotherpsk";
    size_t expected_key_len = 16;
    unsigned char *pskdh_key = malloc(16);
    unsigned char *pskdh_key1 = malloc(16);
    unsigned char *pskdh_key2 = malloc(16);
    psk_dh(psk, pskdh_key);
    free(pskdh_key);
    free(pskdh_key1);
    free(pskdh_key2);
}

void ibe_test()
{
    bn_t s;
    g1_t pub;
    g2_t prv;
    uint8_t in[10], out[10 + 2 * RLC_FP_BYTES + 1];
    char *id = "Alice";
    size_t il, ol;
    int result;

    bn_null(s);
    g1_null(pub);
    g2_null(prv);

    bn_new(s);
    g1_new(pub);
    g2_new(prv);

    il = 10;
    ol = il + 2 * RLC_FP_BYTES + 1;
    cp_ibe_gen(s, pub);
    cp_ibe_gen_prv(prv, id, s);
    cp_ibe_enc(out, &ol, in, il, id, pub);
    cp_ibe_dec(out, &il, out, ol, prv);

    bn_free(s);
    g1_free(pub);
    g2_free(prv);
}

void bls_test()
{
    bn_t d;
    g1_t s;
    g2_t q;
    uint8_t m[5] = {0, 1, 2, 3, 4};

    bn_null(d);
    g1_null(s);
    g2_null(q);

    bn_new(d);
    g1_new(s);
    g2_new(q);

    cp_bls_gen(d, q);
    cp_bls_sig(s, m, sizeof(m), d);
    cp_bls_ver(s, m, sizeof(m), q);
    /* Check adversarial signature. */
    memset(m, 0, sizeof(m));
    g2_set_infty(q);
    cp_bls_ver(s, m, sizeof(m), q);

    bn_free(d);
    g1_free(s);
    g2_free(q);
    bn_free(d);
    g1_free(s);
    g2_free(q);
}

void ibbe_test()
{
    ibbe_params_t params;
    ibbe_prv_t prv;
    ibbe_ct_t ct;
    uint8_t msg[] = "Hello IBBE!";
    size_t msg_len = strlen((char *)msg);
    uint8_t out[msg_len + 16]; // For storing derived plaintext
    size_t out_len = sizeof(out);
    char *ids[] = {"Alice", "Bob", "Charlie"};
    int aliceIsAReceiver = 1; // 1=true, 0=false

    // Setup with security parameter 256 and max 10 users
    ibbe_setup(&params, 256, 10);
    // Extract private key for Alice
    ibbe_extract(&prv, ids[0], &params);
    if (!aliceIsAReceiver)
    {
        ids[0] = "Alese"; // Removing id of Alice so she should not be able to decrypt
    }
    // Encrypt message for all three identities
    ibbe_encrypt(&ct, msg, msg_len, ids, 3, &params);
    ibbe_decrypt(out, &out_len, &ct, &prv, "Alice", &params);

    // Cleanup ciphertext
    for (int i = 0; i < ct.num_ids; i++)
        free(ct.ids[i]);
    free(ct.ids);
    free(ct.ct);

    // Cleanup params
    bn_free(params.gamma);
    bn_free(params.p);
    g1_free(params.g);
    g2_free(params.h);
    gt_free(params.v);
    for (int i = 0; i <= params.max_users; i++)
        g2_free(params.h_gamma[i]);
    free(params.h_gamma);

    // Cleanup private key
    g1_free(prv.sk);
}

int main(void)
{
    if (core_init() != RLC_OK) // init library
    {
        core_clean();
        return 1;
    }
    measure_cycles("HKDF test", hkdf_test);
    measure_cycles("PSK-DH test", pskdh_test);

    if (pc_param_set_any() == RLC_OK) {
        measure_cycles("IBE test", ibe_test);
        measure_cycles("BLS test", bls_test);
        measure_cycles("IBBE test", ibbe_test);
    } 
    return 0;
}

// gcc -o bin/perf_benchmark perf_benchmark.c pskdh.c ibbe.c -I ../relic-0.7.0/include -I relic-target/include relic-target/lib/librelic_s.a -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lcrypto && ./bin/perf_benchmark

// For linux
// gcc -o perf_benchmark perf_benchmark.c pskdh.c ibbe.c -I../relic/include -I../relic-target/include ../relic-target/lib/librelic_s.a -I/home/linuxbrew/.linuxbrew/opt/openssl@3/include -L/home/linuxbrew/.linuxbrew/opt/openssl@3/lib -lcrypto && ./perf_benchmark
