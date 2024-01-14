#include "../utils/utils.h"
#include "crypto.h"
#include "jansson.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cmls_crypto_test(const json_t* entry) {
	size_t suite_index_1 =
		json_integer_value(json_object_get(entry, "cipher_suite"));

	if(suite_index_1 > cmls_max_ciphersuite) {
		fprintf(
			stderr,
			"\e[1;31mUnsupported cipher suite: %zu\e[m\n",
			suite_index_1
		);
		return;
	}

	cmls_CipherSuite suite = cmls_ciphersuites[suite_index_1 - 1];
	if(suite.skip) {
		fprintf(stderr, "\e[1;31mSkipping suite %zu\e[m\n", suite_index_1);
		return;
	}

	///// RefHash /////
	{
		const json_t* j     = json_object_get(entry, "ref_hash");
		const char*   label = json_string_value(json_object_get(j, "label"));

		size_t               data_len = 0;
		const unsigned char* data     = decode_hex(
            json_string_value(json_object_get(j, "value")),
            &data_len
        );

		size_t               hash_len = 0;
		const unsigned char* hash_want =
			decode_hex(json_string_value(json_object_get(j, "out")), &hash_len);

		const unsigned char* hash_have =
			cmls_crypto_RefHash(suite, label, data, data_len);
		assert(memcmp(hash_want, hash_have, hash_len) == 0);

		free((char*) hash_have);
		free((char*) hash_want);
		free((char*) data);
	}

	///// ExpandWithLabel /////
	{
		const json_t* j = json_object_get(entry, "expand_with_label");

		size_t               context_len = 0;
		const unsigned char* context     = decode_hex(
            json_string_value(json_object_get(j, "context")),
            &context_len
        );

		const char* label = json_string_value(json_object_get(j, "label"));

		size_t length = json_integer_value(json_object_get(j, "length"));

		size_t               secret_len = 0;
		const unsigned char* secret     = decode_hex(
            json_string_value(json_object_get(j, "secret")),
            &secret_len
        );

		const unsigned char* out_want =
			decode_hex(json_string_value(json_object_get(j, "out")), NULL);

		const unsigned char* out_have = cmls_crypto_ExpandWithLabel(
			suite,
			secret,
			secret_len,
			label,
			context,
			context_len,
			length
		);
		assert(memcmp(out_want, out_have, length) == 0);

		free((char*) out_have);
		free((char*) out_want);
		free((char*) secret);
		free((char*) context);
	}

	///// DeriveSecret /////
	{
		const json_t* j = json_object_get(entry, "derive_secret");

		const char* label = json_string_value(json_object_get(j, "label"));

		size_t               secret_len = 0;
		const unsigned char* secret     = decode_hex(
            json_string_value(json_object_get(j, "secret")),
            &secret_len
        );

		size_t               out_len = 0;
		const unsigned char* out_want =
			decode_hex(json_string_value(json_object_get(j, "out")), &out_len);

		const unsigned char* out_have =
			cmls_crypto_DeriveSecret(suite, secret, secret_len, label);
		assert(memcmp(out_want, out_have, out_len) == 0);

		free((char*) out_have);
		free((char*) out_want);
		free((char*) secret);
	}

	///// DeriveTreeSecret /////
	{
		const json_t* j = json_object_get(entry, "derive_tree_secret");

		uint32_t generation =
			json_integer_value(json_object_get(j, "generation"));

		const char* label = json_string_value(json_object_get(j, "label"));

		size_t length = json_integer_value(json_object_get(j, "length"));

		size_t               secret_len = 0;
		const unsigned char* secret     = decode_hex(
            json_string_value(json_object_get(j, "secret")),
            &secret_len
        );

		const unsigned char* out_want =
			decode_hex(json_string_value(json_object_get(j, "out")), NULL);

		const unsigned char* out_have = cmls_crypto_DeriveTreeSecret(
			suite,
			secret,
			secret_len,
			label,
			generation,
			length
		);
		assert(memcmp(out_want, out_have, length) == 0);

		free((char*) out_have);
		free((char*) out_want);
		free((char*) secret);
	}

	///// SignWithLabel /////
	{
		const json_t* j = json_object_get(entry, "sign_with_label");

		size_t               content_len = 0;
		const unsigned char* content     = decode_hex(
            json_string_value(json_object_get(j, "content")),
            &content_len
        );

		const char* label = json_string_value(json_object_get(j, "label"));

		size_t               priv_len = 0;
		const unsigned char* priv     = decode_hex(
            json_string_value(json_object_get(j, "priv")),
            &priv_len
        );

		size_t               pub_len = 0;
		const unsigned char* pub =
			decode_hex(json_string_value(json_object_get(j, "pub")), &pub_len);

		size_t               sig_want_len = 0;
		const unsigned char* sig_want     = decode_hex(
            json_string_value(json_object_get(j, "signature")),
            &sig_want_len
        );

		assert(cmls_crypto_VerifyWithLabel(
			suite,
			pub,
			pub_len,
			label,
			content,
			content_len,
			sig_want,
			sig_want_len
		));

		unsigned char* sig_have     = NULL;
		size_t         sig_have_len = 0;
		cmls_crypto_SignWithLabel(
			suite,
			priv,
			priv_len,
			label,
			content,
			content_len,
			&sig_have,
			&sig_have_len
		);
		assert(memcmp(sig_want, sig_have, sig_want_len) == 0);

		assert(cmls_crypto_VerifyWithLabel(
			suite,
			pub,
			pub_len,
			label,
			content,
			content_len,
			sig_have,
			sig_have_len
		));

		free((char*) sig_have);
		free((char*) sig_want);
		free((char*) pub);
		free((char*) priv);
		free((char*) content);
	}
}
