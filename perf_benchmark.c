/**
 * Benchmarking using the linux tool perf
 */

#include <stdio.h>
#include "relic.h"
#include "relic_test.h"
#include "pskdh.h"
#include "ibbe.h"
#include "aes.h"
#include <linux/perf_event.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/wait.h>

// Amount of times the measurement of CPU cycles for each method is repeated.
static int DEFAULT_RUNS = 1000;

int load_file_as_uint8(const char *filename, uint8_t **buffer, size_t *length)
{
	FILE *file = fopen(filename, "rb"); // open in binary mode
	if (!file)
	{
		perror("Failed to open file");
		return -1;
	}

	// Get file size
	fseek(file, 0, SEEK_END);
	*length = ftell(file);
	fseek(file, 0, SEEK_SET);

	*buffer = (uint8_t *)malloc(*length);
	if (!*buffer)
	{
		perror("Memory allocation failed");
		fclose(file);
		return -1;
	}

	// Read the file into buffer
	size_t read_bytes = fread(*buffer, 1, *length, file);
	if (read_bytes != *length)
	{
		perror("File read failed");
		free(*buffer);
		fclose(file);
		return -1;
	}

	fclose(file);
	return 0;
}

uint8_t *msg;
size_t msg_len;
int8_t iv_value[16] = {
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F};
uint8_t *iv = (uint8_t *)iv_value;

static long perf_event_open(struct perf_event_attr *pe, pid_t pid,
                            int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, pe, pid, cpu, group_fd, flags);
}

/** Get peak memory held in physical RAM (in kilobytes) for the current process */
long get_peak_mem_usage()
{
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss;
}

void measure_cycles(const char *name, void (*func)(), int runs)
{
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
    if (fd == -1)
    {
        perror("perf_event_open failed");
        return;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    for (size_t i = 0; i < runs; i++)
    {
        func();
    }

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    read(fd, &count, sizeof(count));

    printf("%s: %lld CPU cycles\n", name, count / runs);
    close(fd);
}

long read_energy() {
    FILE *fp = fopen("/sys/class/powercap/intel-rapl:0/energy_uj", "r");
    if (!fp) {
        perror("fopen");
        exit(1);
    }
    long energy;
    fscanf(fp, "%lld", &energy);
    fclose(fp);
    return energy;
}

/**
 * Measures a methods average CPU cycles, power consumption and peak RAM usage after 'runs' iterations
 */
void measure_method(const char *name, void (*func)(), int runs)
{
    pid_t pid = fork(); // starts new process to reset mem usage
    if (pid == 0)
    {
        struct timespec start_time, end_time;
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        long start = read_energy();
        measure_cycles(name, func, runs);
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        long seconds = end_time.tv_sec - start_time.tv_sec;
        long nanoseconds = end_time.tv_nsec - start_time.tv_nsec;
        long total_microseconds = (seconds * 1e6) + (nanoseconds / 1e3);
        printf("%s: Avg Time: %ld microseconds\n", name, total_microseconds / runs);
        printf("%s: %ld Kb RAM usage\n", name, get_peak_mem_usage());
        long end = read_energy();
        long microjoules = end - start;
        printf("Energy used: %ld microjoules\n", microjoules / runs);
        exit(0);
    }
    else
    {
        waitpid(pid, NULL, 0); // Wait for child
    }
}

void hkdf_test()
{
    unsigned char premaster_secret[] = "secretkey";
    unsigned char *master_secret = hkdf(premaster_secret);
}

void pskdh_test()
{
    const char *psk = "asecretpsk123456789010111213141";
    size_t key_len = 32;
    unsigned char *pskdh_key = malloc(key_len);
    psk_dh(psk, pskdh_key);
    free(pskdh_key);
}

void ibe_test()
{
	bn_t s;
	g1_t pub;
	g2_t prv;
	uint8_t aes_key[] = "SECRET_AES_KEY_1234567890111213";
	size_t aes_key_length = 32;
	size_t ct_aes_key_len = aes_key_length + 2 * RLC_FP_BYTES + 1;
	uint8_t *ct_aes_key = malloc(ct_aes_key_len);
	uint8_t *out_aes_key = malloc(aes_key_length);
	char *id = "Alice";

	size_t ct_len = msg_len + 2 * RLC_FP_BYTES + 1;
	uint8_t *ct = malloc(ct_len);
	size_t plaintext_len = msg_len;
	uint8_t *plaintext = malloc(plaintext_len);

    int result;

    bn_null(s);
    g1_null(pub);
    g2_null(prv);

    bn_new(s);
    g1_new(pub);
    g2_new(prv);

    cp_ibe_gen(s, pub);
    cp_ibe_gen_prv(prv, id, s);
    aes_256_cbc_encrypt(msg, msg_len, aes_key, iv, ct);
    cp_ibe_enc(ct_aes_key, &ct_aes_key_len, aes_key, aes_key_length, id, pub);
    cp_ibe_dec(out_aes_key, &aes_key_length, ct_aes_key, ct_aes_key_len, prv);
    aes_256_cbc_decrypt(ct, ct_len, out_aes_key, iv, plaintext);

    bn_free(s);
    g1_free(pub);
    g2_free(prv);
    free(ct_aes_key);
    free(out_aes_key);
    free(ct);
    free(plaintext);
}

void bls_test()
{
    bn_t d;
    g1_t s;
    g2_t q;

    bn_null(d);
    g1_null(s);
    g2_null(q);

    bn_new(d);
    g1_new(s);
    g2_new(q);

    cp_bls_gen(d, q);
    cp_bls_sig(s, msg, msg_len, d);
    cp_bls_ver(s, msg, msg_len, q);
    /* Check adversarial signature. */
    memset(msg, 0, msg_len);
    g2_set_infty(q);
    cp_bls_ver(s, msg, msg_len, q);

    bn_free(d);
    g1_free(s);
    g2_free(q);
}

void ibbe_test()
{
    ibbe_params_t params;
    ibbe_prv_t prv;
    ibbe_ct_t ct;
    uint8_t out[msg_len + 16]; // For storing derived plaintext
    size_t out_len = sizeof(out);
    // char *ids[] = {"Alice", "Bob", "Charlie"};
    char *ids[] = {
		"Alice", "Bob", "Charlie", "David", "Eve", "Frank", "Grace", "Hannah",
		"Ian", "Jack", "Karen", "Liam", "Mona", "Nathan", "Olivia", "Paul",
		"Quinn", "Rachel", "Sam", "Tina", "Uma", "Victor", "Wendy", "Xander",
		"Yara", "Zane", "Abby", "Ben", "Cindy", "Derek", "Ella", "Fred",
		"Gina", "Harry", "Isla", "Jake", "Kylie", "Leo", "Mia", "Noah",
		"Oscar", "Penny", "Quincy", "Rita", "Steve", "Tara", "Ulysses", "Vera",
		"Will", "Xenia", "Yusuf", "Zoe", "Amber", "Brandon", "Clara", "Dylan",
		"Elena", "Felix", "Georgia", "Henry", "Ivy", "Joel", "Kate", "Logan"};

    ibbe_setup(&params, 256, 70);
    ibbe_extract(&prv, ids[0], &params);
    ibbe_encrypt(&ct, msg, msg_len, ids, 64, &params);
    ibbe_decrypt(out, &out_len, &ct, &prv, "Alice", &params);

    for (int i = 0; i < ct.num_ids; i++)
        free(ct.ids[i]);
    free(ct.ids);
    free(ct.ct);
    bn_free(params.gamma);
    bn_free(params.p);
    g1_free(params.g);
    g2_free(params.h);
    gt_free(params.v);
    for (int i = 0; i <= params.max_users; i++)
        g2_free(params.h_gamma[i]);
    free(params.h_gamma);
    g1_free(prv.sk);
}

int main(void)
{
    if (core_init() != RLC_OK) // init library
    {
        core_clean();
        return 1;
    }

    load_file_as_uint8("6mB.txt", &msg, &msg_len);

    // printf("**** Average CPU cycles and max RAM usage for each method in %d runs ****\n", DEFAULT_RUNS);
    measure_method("HKDF", hkdf_test, DEFAULT_RUNS);
    measure_method("PSK-DH", pskdh_test, DEFAULT_RUNS);

    if (pc_param_set_any() == RLC_OK)
    {
        measure_method("IBE", ibe_test, DEFAULT_RUNS);
        measure_method("BLS", bls_test, DEFAULT_RUNS);
        measure_method("IBBE", ibbe_test, DEFAULT_RUNS);
    }
    return 0;
}

// gcc -o bin/perf_benchmark perf_benchmark.c pskdh.c ibbe.c aes.c -I ../relic-0.7.0/include -I relic-target/include relic-target/lib/librelic_s.a -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lcrypto && ./bin/perf_benchmark

// For linux
// sudo gcc -o perf_benchmark perf_benchmark.c pskdh.c ibbe.c aes.c -I../relic/include -I../relic-target/include ../relic-target/lib/librelic_s.a -I/home/linuxbrew/.linuxbrew/opt/openssl@3/include -L/home/linuxbrew/.linuxbrew/opt/openssl@3/lib -lcrypto && sudo ./perf_benchmark





// Tried to divide the ibbe method into different parts so i could measure each ram usage. It did not work and seemed to not be able to encrypt and decrpyt. 
// Decided to keep it simple and just measure the whole ibbe_test and then estimate CPU and RAM usage based on time it takes to finish the method. 
// The peak RAM is okay to measure for all methods (like ibbe_test) and not child methods (like ibbe_extract) and not for an individual one. We can argue that you need at least this amount of RAM to implement the protocol on a device. 

// 
// ibbe_params_t params;
// ibbe_prv_t prv;
// uint8_t msg[] = "Hello IBBE!";
// ibbe_ct_t ct;
// size_t msg_len;
// char *ids[] = {"Alice", "Bob", "Charlie"};
// uint8_t out[sizeof(ct)]; // For storing derived plaintext
// size_t out_len = sizeof(out);

// void ibbe_setup_test()
// {
//     ibbe_setup(&params, 256, 10);
// }

// void ibbe_extract_test()
// {
//     ibbe_extract(&prv, ids[0], &params);
// }
// void ibbe_encrypt_test()
// {
//     msg_len = strlen((char *)msg);
//     ibbe_encrypt(&ct, msg, msg_len, ids, 3, &params);
// }

// void ibbe_decrypt_test()
// {
//     ibbe_decrypt(out, &out_len, &ct, &prv, ids[0], &params);
// }

// void ibbe_clean()
// {
//     // Cleanup ciphertext
//     for (int i = 0; i < ct.num_ids; i++)
//         free(ct.ids[i]);
//     free(ct.ids);
//     free(ct.ct);
//     // Cleanup params
//     bn_free(params.gamma);
//     bn_free(params.p);
//     g1_free(params.g);
//     g2_free(params.h);
//     gt_free(params.v);
//     for (int i = 0; i <= params.max_users; i++)
//         g2_free(params.h_gamma[i]);
//     free(params.h_gamma);

//     // Cleanup private key
//     g1_free(prv.sk);
// }
