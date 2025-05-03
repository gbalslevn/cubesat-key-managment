/**
 * Tests and benchmarking of various cryptographic protocols.
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"
#include "pskdh.h"
#include "ibbe.h"

static int hkdf_test(void) {
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

static int pskdh_test(void)
{
	int code = RLC_ERR;
	const char *psk = "asecretpsk";
	const char *anotherpsk = "anotherpsk";
	size_t expected_key_len = 16;
	unsigned char *pskdh_key = malloc(16);
	unsigned char *pskdh_key1 = malloc(16);
	unsigned char *pskdh_key2 = malloc(16);

	RLC_TRY
	{

		TEST_CASE("pskdh is succesfull")
		{
			psk_dh(psk, pskdh_key);
			TEST_ASSERT(pskdh_key1 != NULL, end);
			TEST_ASSERT(memcmp(pskdh_key, pskdh_key, expected_key_len) == 0, end);
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

		BENCH_RUN("psk_dh")
		{
			BENCH_ADD(psk_dh(psk, pskdh_key));
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
	free(pskdh_key1);
	free(pskdh_key2);
	return code;
}

static int ibe_test(void)
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
			// bench_init()
			// bench_overhead();
			// bench_clean();
		}
		BENCH_END;

		BENCH_RUN("upk_ibe_gen")
		{
			BENCH_ADD(cp_ibe_gen_prv(prv, id, s));
		}
		BENCH_END;

		// BENCH_RUN("cp_ibe_enc")
		// {
		// 	in_len = sizeof(in);
		// 	out_len = in_len + 2 * RLC_FP_BYTES + 1;
		// 	rand_bytes(in, sizeof(in));
		// 	BENCH_ADD(cp_ibe_enc(out, &out_len, in, in_len, id, pub));
		// 	cp_ibe_dec(out, &out_len, out, out_len, prv);
		// }
		// BENCH_END;

		// BENCH_RUN("cp_ibe_dec")
		// {
		// 	in_len = sizeof(in);
		// 	out_len = in_len + 2 * RLC_FP_BYTES + 1;
		// 	rand_bytes(in, sizeof(in));
		// 	cp_ibe_enc(out, &out_len, in, in_len, id, pub);
		// 	BENCH_ADD(cp_ibe_dec(out, &out_len, out, out_len, prv));
		// }
		// BENCH_END;
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

static int bls_test(void)
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
			BENCH_ADD(cp_bls_sig(s, m, 5, d));
		}
		BENCH_END;

		BENCH_RUN("cp_bls_ver")
		{
			BENCH_ADD(cp_bls_ver(s, m, 5, q));
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

static int ibbe_test()
{
	int code = RLC_ERR;
	ibbe_params_t params;
	ibbe_prv_t prv;
	ibbe_ct_t ct;
	uint8_t msg[] = "Hello IBBE!";
	// rand_bytes(msg, sizeof(msg)); // For generating random message
	size_t msg_len = strlen((char *)msg);
	uint8_t out[msg_len + 16]; // For storing derived plaintext
	size_t out_len = sizeof(out);
	char *ids[] = {"Alice", "Bob", "Charlie"};
	int aliceIsAReceiver = 1; // 1=true, 0=false

	RLC_TRY
	{
		TEST_CASE("Delerablée IBBE scheme is correct")
		{
			// Setup with security parameter 256 and max 10 users
			TEST_ASSERT(ibbe_setup(&params, 256, 10) == RLC_OK, end);

			// Extract private key for Alice
			TEST_ASSERT(ibbe_extract(&prv, ids[0], &params) == RLC_OK, end);

			// Encrypt message for all three identities
			// printf("************* ENCRYPT *************\n");
			if (!aliceIsAReceiver)
			{
				ids[0] = "Alese"; // Removing id of Alice so she should not be able to decrypt
			}
			TEST_ASSERT(ibbe_encrypt(&ct, msg, msg_len, ids, 3, &params) == RLC_OK, end);
			// printf("msg is: ");
			// print_char(msg, msg_len);
			// printf("ct is: ");
			// print_hex(ct.ct, ct.ct_len);

			// Alice should be able to decrypt
			// printf("************* ENCRYPT *************\n");
			TEST_ASSERT(ibbe_decrypt(out, &out_len, &ct, &prv, "Alice", &params) == RLC_OK, end);
			// printf("recovered plaintext is: ");
			// print_char(out, out_len);

			// derived plaintext should be the same as the provided message.
			TEST_ASSERT(memcmp(msg, out, msg_len) == 0, end);
		}
		TEST_END;

		BENCH_RUN("ibbe_setup")
		{
			BENCH_ADD(ibbe_setup(&params, 256, 10));
		}
		BENCH_END;

		BENCH_RUN("ibbe_extract")
		{
			BENCH_ADD(ibbe_extract(&prv, ids[0], &params));
		}
		BENCH_END;

		BENCH_RUN("ibbe_encrypt")
		{
			BENCH_ADD(ibbe_encrypt(&ct, msg, msg_len, ids, 3, &params));
		}
		BENCH_END;

		BENCH_RUN("ibbe_decrypt")
		{
			BENCH_ADD(ibbe_decrypt(out, &out_len, &ct, &prv, "Alice", &params));
		}
		BENCH_END;
		// Cleanup ciphertext
		for (int i = 0; i < ct.num_ids; i++)
			free(ct.ids[i]);
		free(ct.ids);
		free(ct.ct);
	}
	RLC_CATCH_ANY
	{
		RLC_ERROR(end);
	}
	code = RLC_OK;

end:
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

	// The bench runs methods 10000 times and takes the average.

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
	}
	if (ibbe_test() != RLC_OK)
	{
		core_clean();
		return 1;
	}

	core_clean();
	return 0;
}

// gcc -o benchmark benchmark.c -I ../../relic-0.7.0/include -I../relic-target/include ../relic-target/lib/librelic_s.a -L/opt/homebrew/lib -lgmp && ./benchmark
// Also works without The GNU Multiple Precision Arithmetic Library
// gcc -o benchmark benchmark.c -I ../../relic-0.7.0/include -I../relic-target/include ../relic-target/lib/librelic_s.a && ./benchmark

// For testing the c test files from the relic library has been compiled into runnables in relic-target/bin

// For including a file like pskdh you would need to do,
// gcc -o benchmark benchmark.c -I ../relic-0.7.0/include -I relic-target/include relic-target/lib/librelic_s.a -L/opt/homebrew/lib -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lcrypto pskdh.c && ./benchmark

// gcc -o benchmark benchmark.c -I ../relic-0.7.0/include -I relic-target/include relic-target/lib/librelic_s.a -L/opt/homebrew/lib -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lcrypto pskdh.c ibbe.c && ./benchmark
