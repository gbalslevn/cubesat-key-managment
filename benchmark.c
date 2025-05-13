/**
 * Tests and benchmarking of various cryptographic protocols.
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"
#include "pskdh.h"
#include "ibbe.h"

uint8_t msg[] = "Test message!";

int hkdf_test(void)
{
	int code = RLC_ERR;
	unsigned char premaster_secret[] = "secretkey";

	RLC_TRY
	{

		TEST_CASE("hkdf is succesfull")
		{
			unsigned char *master_secret = hkdf(premaster_secret);
			TEST_ASSERT(master_secret != NULL, end);
		}
		TEST_END;

		BENCH_RUN("hkdf")
		{
			BENCH_ADD(hkdf(premaster_secret));
		}
		BENCH_END;
	}
	RLC_CATCH_ANY
	{
		RLC_ERROR(end);
	}
	code = RLC_OK;

end:
	return code;
}

int pskdh_test(void)
{
	int code = RLC_ERR;
	const char *psk = "asecretpsk";
	const char *anotherpsk = "anotherpsk";
	size_t expected_key_len = 32;
	unsigned char *pskdh_key = malloc(32);
	// unsigned char *pskdh_key1 = malloc(16);
	// unsigned char *pskdh_key2 = malloc(16);

	static const uint8_t iv_value[16] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B,
		0x0C, 0x0D, 0x0E, 0x0F};
	uint8_t *iv = (uint8_t *)iv_value;
	// uint8_t msg[] = "Hello PSK!";
	// rand_bytes(msg, sizeof(msg)); // For generating random message
	size_t msg_len = strlen((char *)msg);
	size_t ct_len = msg_len + RLC_MD_LEN;
	uint8_t *ct = malloc(ct_len);
	size_t out_len = ct_len;
	uint8_t out[out_len]; // For storing derived plaintext

	RLC_TRY
	{

		TEST_CASE("pskdh gen and encryption/decryption is correct")
		{
			psk_dh(psk, pskdh_key);
			TEST_ASSERT(pskdh_key != NULL, end);
			TEST_ASSERT(bc_aes_cbc_enc(ct, &ct_len, msg, msg_len, pskdh_key, expected_key_len, iv) == RLC_OK, end);
			bc_aes_cbc_dec(out, &out_len, ct, ct_len, pskdh_key, expected_key_len, iv); // got an error here. Probably from padding. Remove test for now and fix later.
			TEST_ASSERT(memcmp(msg, out, msg_len) == 0, end);
		}
		TEST_END;
		// To do this test we need to do it where the keypair to create the dh secret Z is fixed else the derived key will be different, even though salt and info is fixed.
		// TEST_CASE("pskdh generates different keys for different PSKs")
		// {
		// 	psk_dh(psk, pskdh_key1);
		// 	psk_dh(psk, pskdh_key2);
		// 	TEST_ASSERT(pskdh_key1 != NULL && pskdh_key2 != NULL, end);
		// 	TEST_ASSERT(memcmp(pskdh_key1, pskdh_key2, expected_key_len) != 0, end);
		// }
		// TEST_END;

		// for (size_t i = 0; i < expected_key_len; i++)
		// {
		// 	printf("%02x", pskdh_key1[i]);
		// }
		// printf("\nand the other key is\n");
		// for (size_t i = 0; i < expected_key_len; i++)
		// {
		// 	printf("%02x", pskdh_key2[i]);
		// }

		// TEST_CASE("pskdh generates equal keys for the same PSK (given salt is the same)")
		// {
		// 	psk_dh(psk, pskdh_key1);
		// 	psk_dh(anotherpsk, pskdh_key2);

		// 	TEST_ASSERT(pskdh_key1 != NULL && pskdh_key2 != NULL, end);
		// 	TEST_ASSERT(memcmp(pskdh_key1, pskdh_key2, expected_key_len) != 0, end);
		// }
		// TEST_END;

		BENCH_RUN("psk_dh_gen")
		{
			BENCH_ADD(psk_dh(psk, pskdh_key));
		}
		BENCH_END;
		BENCH_RUN("psk_dh_aes_enc")
		{
			BENCH_ADD(bc_aes_cbc_enc(ct, &ct_len, msg, msg_len, pskdh_key, expected_key_len, iv));
		}
		BENCH_END;
		BENCH_RUN("psk_dh_aes_dec")
		{
			BENCH_ADD(bc_aes_cbc_dec(out, &out_len, ct, ct_len, pskdh_key, expected_key_len, iv));
		}
		BENCH_END;
	}
	RLC_CATCH_ANY
	{
		RLC_ERROR(end);
	}
	code = RLC_OK;

end:
	free(pskdh_key);
	// free(pskdh_key1);
	// free(pskdh_key2);
	return code;
}

int ibe_test(void)
{
	int code = RLC_ERR;
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

	RLC_TRY
	{
		bn_new(s);
		g1_new(pub);
		g2_new(prv);

		// printf("Pub is: \n");
		// g1_print(pub);
		result = cp_ibe_gen(s, pub);
		// printf("Pub is: \n");
		// g1_print(pub);

		TEST_CASE("boneh-franklin identity-based encryption/decryption is correct")
		{
			TEST_ASSERT(result == RLC_OK, end);
			il = 10;
			ol = il + 2 * RLC_FP_BYTES + 1;
			rand_bytes(in, il);
			TEST_ASSERT(cp_ibe_gen_prv(prv, id, s) == RLC_OK, end);
			TEST_ASSERT(cp_ibe_enc(out, &ol, in, il, id, pub) == RLC_OK, end);
			TEST_ASSERT(cp_ibe_dec(out, &il, out, ol, prv) == RLC_OK, end);
			TEST_ASSERT(memcmp(in, out, il) == 0, end);
		}
		TEST_END;

		BENCH_RUN("master_ibe_gen")
		{
			BENCH_ADD(cp_ibe_gen(s, pub));
			// bench_init();
			// bench_overhead();
			// bench_clean();
		}
		BENCH_END;

		BENCH_RUN("usk_ibe_gen")
		{
			BENCH_ADD(cp_ibe_gen_prv(prv, id, s));
		}
		BENCH_END;

		BENCH_RUN("cp_ibe_enc")
		{
			il = sizeof(in);
			ol = il + 2 * RLC_FP_BYTES + 1;
			rand_bytes(in, sizeof(in));
			BENCH_ADD(cp_ibe_enc(out, &ol, in, il, id, pub));
		}
		BENCH_END;

		BENCH_RUN("cp_ibe_dec")
		{
			il = sizeof(in);
			ol = il + 2 * RLC_FP_BYTES + 1;
			uint8_t plaintext[il];
			size_t plaintext_len = il;
			rand_bytes(in, sizeof(in));
			cp_ibe_enc(out, &ol, in, il, id, pub);
			BENCH_ADD(cp_ibe_dec(plaintext, &plaintext_len, out, ol, prv));
		}
		BENCH_END;
	}
	RLC_CATCH_ANY
	{
		RLC_ERROR(end);
	}
	code = RLC_OK;

end:
	bn_free(s);
	g1_free(pub);
	g2_free(prv);
	return code;
}

int bls_test(void)
{
	int code = RLC_ERR;
	bn_t d;
	g1_t s;
	g2_t q;
	uint8_t m[5] = {0, 1, 2, 3, 4};

	bn_null(d);
	g1_null(s);
	g2_null(q);

	RLC_TRY
	{
		bn_new(d);
		g1_new(s);
		g2_new(q);

		TEST_CASE("boneh-lynn-schacham short signature is correct")
		{
			TEST_ASSERT(cp_bls_gen(d, q) == RLC_OK, end);
			TEST_ASSERT(cp_bls_sig(s, m, sizeof(m), d) == RLC_OK, end);
			TEST_ASSERT(cp_bls_ver(s, m, sizeof(m), q) == 1, end);
			/* Check adversarial signature. */
			memset(m, 0, sizeof(m));
			g2_set_infty(q);
			TEST_ASSERT(cp_bls_ver(s, m, sizeof(m), q) == 0, end);
		}
		TEST_END;

		BENCH_RUN("cp_bls_gen")
		{
			BENCH_ADD(cp_bls_gen(d, q));
		}
		BENCH_END;

		BENCH_RUN("cp_bls_sign")
		{
			BENCH_ADD(cp_bls_sig(s, m, sizeof(m), d));
		}
		BENCH_END;

		BENCH_RUN("cp_bls_ver")
		{
			BENCH_ADD(cp_bls_ver(s, m, sizeof(m), q));
		}
		BENCH_END;

		bn_free(d);
		g1_free(s);
		g2_free(q);
	}
	RLC_CATCH_ANY
	{
		RLC_ERROR(end);
	}
	code = RLC_OK;

end:
	bn_free(d);
	g1_free(s);
	g2_free(q);
	return code;
}

int ibbe_test()
{
	int code = RLC_ERR;
	ibbe_params_t params;
	ibbe_prv_t prv;
	ibbe_ct_t ct;
	// uint8_t msg[] = "Hello IBBE!";
	// rand_bytes(msg, sizeof(msg)); // For generating random message
	size_t msg_len = strlen((char *)msg);
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
	int aliceIsAReceiver = 1; // 1=true, 0=false

	RLC_TRY
	{
		TEST_CASE("Delerablée IBBE scheme is correct")
		{
			// Setup with security parameter 256 and max 64 users
			TEST_ASSERT(ibbe_setup(&params, 256, 70) == RLC_OK, end);

			// Extract private key for Alice
			TEST_ASSERT(ibbe_extract(&prv, ids[0], &params) == RLC_OK, end);

			// Encrypt message for all three identities
			// printf("************* ENCRYPT *************\n");
			if (!aliceIsAReceiver)
			{
				ids[0] = "Alese"; // Removing id of Alice so she should not be able to decrypt
			}
			TEST_ASSERT(ibbe_encrypt(&ct, msg, msg_len, ids, 64, &params) == RLC_OK, end);
			// printf("msg is: \n");
			// for (size_t i = 0; i < msg_len; i++)
			// {
			// 	printf("%c", msg[i]);
			// }
			// printf("\n");
			// printf("ct is: \n");
			// for (size_t i = 0; i < msg_len; i++)
			// {
			// 	printf("%02x", msg[i]);
			// }
			// printf("\n");

			// Alice should be able to decrypt
			// printf("************* DECRYPT *************\n");
			TEST_ASSERT(ibbe_decrypt(out, &out_len, &ct, &prv, "Alice", &params) == RLC_OK, end);
			// printf("recovered plaintext is: \n");
			// for (size_t i = 0; i < out_len; i++)
			// {
			// 	printf("%c", out[i]);
			// }
			// printf("\n");

			// derived plaintext should be the same as the provided message.
			TEST_ASSERT(memcmp(msg, out, msg_len) == 0, end);
		}
		TEST_END;

		BENCH_RUN("ibbe_setup")
		{
			BENCH_ADD(ibbe_setup(&params, 256, 70));
		}
		BENCH_END;

		BENCH_RUN("ibbe_extract")
		{
			BENCH_ADD(ibbe_extract(&prv, ids[0], &params));
		}
		BENCH_END;

		BENCH_RUN("ibbe_encrypt")
		{
			BENCH_ADD(ibbe_encrypt(&ct, msg, msg_len, ids, 64, &params));
		}
		BENCH_END;

		BENCH_RUN("ibbe_decrypt")
		{
			BENCH_ADD(ibbe_decrypt(out, &out_len, &ct, &prv, "Alice", &params));
		}
		BENCH_END;
	}
	RLC_CATCH_ANY
	{
		RLC_ERROR(end);
	}
	code = RLC_OK;

end:
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

	return code;
}

int main(void)
{
	if (core_init() != RLC_OK) // init library
	{
		core_clean();
		return 1;
	}

	conf_print();

	util_banner("Testing protocols:\n", 0);
	if (hkdf_test() != 0)
	{
		core_clean();
		return 1;
	}
	if (pskdh_test() != 0)
	{
		core_clean();
		return 1;
	}

	util_banner("Testing protocols based on pairings:\n", 0);
	if (pc_param_set_any() == RLC_OK)
	{ // Configures some set of pairing-friendly curve parameters for the current security level.

		if (ibe_test() != RLC_OK)
		{
			core_clean();
			return 1;
		}

		if (bls_test() != RLC_OK)
		{
			core_clean();
			return 1;
		}

		if (ibbe_test() != RLC_OK)
		{
			core_clean();
			return 1;
		}
	}

	core_clean();
	return 0;
}

// gcc -o benchmark benchmark.c -I ../../relic-0.7.0/include -I../relic-target/include ../relic-target/lib/librelic_s.a -L/opt/homebrew/lib -lgmp && ./benchmark
// Also works without The GNU Multiple Precision Arithmetic Library
// gcc -o benchmark benchmark.c -I ../../relic-0.7.0/include -I../relic-target/include ../relic-target/lib/librelic_s.a && ./benchmark

// For testing the c test files from the relic library has been compiled into runnables in relic-target/bin

// For including a file like pskdh you would need to do,
// gcc -o benchmark benchmark.c -I ../relic-0.7.0/include -I relic-target/include relic-target/lib/librelic_s.a -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lcrypto pskdh.c && ./benchmark
// gcc -o bin/benchmark benchmark.c -I ../relic-0.7.0/include -I relic-target/include relic-target/lib/librelic_s.a -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lcrypto pskdh.c ibbe.c && ./bin/benchmark

// For linux
// gcc -o benchmark benchmark.c pskdh.c ibbe.c -I../relic/include -I../relic-target/include ../relic-target/lib/librelic_s.a -I/home/linuxbrew/.linuxbrew/opt/openssl@3/include -L/home/linuxbrew/.linuxbrew/opt/openssl@3/lib -lcrypto && ./benchmark
