/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Tests for implementation of cryptographic protocols.
 *
 * @version $Id$
 * @ingroup test
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"
#include "../pskdh.h"

static int ibe(void)
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
		
		BENCH_RUN("psk_dh")
		{
			BENCH_ADD(psk_dh());
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

static int bls(void)
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

int main(void)
{
	if (core_init() != RLC_OK) // init library
	{
		core_clean();
		return 1;
	}

	util_banner("Testing protocols based on pairings:\n", 0);
	if (pc_param_set_any() == RLC_OK)
	{ // Configures some set of pairing-friendly curve parameters for the current security level.

		if (ibe() != RLC_OK)
		{
			core_clean();
			return 1;
		}

		if (bls() != RLC_OK)
		{
			core_clean();
			return 1;
		}
	}

	core_clean();
	return 0;
}

// gcc -o ibe ibe.c -I ../../relic-0.7.0/include -I../relic-target/include ../relic-target/lib/librelic_s.a -L/opt/homebrew/lib -lgmp && ./ibe
// Also works without The GNU Multiple Precision Arithmetic Library
// gcc -o ibe ibe.c -I ../../relic-0.7.0/include -I../relic-target/include ../relic-target/lib/librelic_s.a && ./ibe

// For testing the c test files from the relic library has been compiled into runnables in relic-target/bin



// For including a file like pskdh you would need to do,
// gcc -o ibe ibe.c -I ../../relic-0.7.0/include -I../relic-target/include ../relic-target/lib/librelic_s.a -L/opt/homebrew/lib -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lcrypto ../pskdh.c && ./ibe
