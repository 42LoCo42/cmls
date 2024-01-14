#include "crypto.h"
#include "../serialize/serialize.h"
#include <assert.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/sha.h>

cmls_CipherSuite cmls_ciphersuites[] = {
	{
		.hash        = SHA256,
		.hash_name   = SN_sha256,
		.hash_length = SHA256_DIGEST_LENGTH,
	},
	{
		.hash        = SHA256,
		.hash_name   = SN_sha256,
		.hash_length = SHA256_DIGEST_LENGTH,
	},
	{
		.hash        = SHA256,
		.hash_name   = SN_sha256,
		.hash_length = SHA256_DIGEST_LENGTH,
	},
	{
		.hash        = SHA512,
		.hash_name   = SN_sha512,
		.hash_length = SHA512_DIGEST_LENGTH,
	},
	{
		.hash        = SHA512,
		.hash_name   = SN_sha512,
		.hash_length = SHA512_DIGEST_LENGTH,
	},
	{
		.hash        = SHA512,
		.hash_name   = SN_sha512,
		.hash_length = SHA512_DIGEST_LENGTH,
	},
	{
		.hash        = SHA384,
		.hash_name   = SN_sha384,
		.hash_length = SHA384_DIGEST_LENGTH,
	},
};

size_t cmls_max_ciphersuite =
	sizeof(cmls_ciphersuites) / sizeof(cmls_ciphersuites[0]);

static EVP_KDF_CTX* ctx = NULL;

static void __attribute__((constructor)) lib_init() {
	EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	ctx          = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);
}

static void __attribute((destructor())) lib_free() {
	EVP_KDF_CTX_free(ctx);
}

static void ctx_set_digest(cmls_CipherSuite suite) {
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string(
			OSSL_KDF_PARAM_DIGEST,
			suite.hash_name,
			strlen(suite.hash_name)
		),
		OSSL_PARAM_construct_end(),
	};
	EVP_KDF_CTX_set_params(ctx, params);
}

static size_t cmls_crypto_kdf_nh(cmls_CipherSuite suite) {
	ctx_set_digest(suite);
	int        mode     = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
		OSSL_PARAM_construct_end(),
	};
	EVP_KDF_CTX_set_params(ctx, params);
	return EVP_KDF_CTX_get_kdf_size(ctx);
}

unsigned char* cmls_crypto_RefHash(
	cmls_CipherSuite     suite,
	const char*          label,
	const unsigned char* data,
	size_t               data_len
) {
	unsigned char* hash = malloc(suite.hash_length);
	if(hash == NULL) return NULL;

	bytes vec = {0};
	cmls_serialize_encode((unsigned char*) label, strlen(label), &vec);
	cmls_serialize_encode(data, data_len, &vec);

	suite.hash(vec.ptr, vec.len, hash);
	vec_free(&vec);
	return hash;
}

unsigned char* cmls_crypto_ExpandWithLabel(
	cmls_CipherSuite     suite,
	const unsigned char* secret,
	size_t               secret_len,
	const char*          label,
	const unsigned char* context,
	size_t               context_len,
	uint16_t             length
) {
	unsigned char* out        = NULL;
	char*          real_label = NULL;
	bytes          info       = {0};

	if((out = malloc(length)) == NULL) goto end;

	// create KDFLabel
	if(asprintf(&real_label, "MLS 1.0 %s", label) < 0) goto end;
	vec_push(&info, length >> (8 * 1));
	vec_push(&info, length >> (8 * 0));
	cmls_serialize_encode(
		(unsigned char*) real_label,
		strlen(real_label),
		&info
	);
	cmls_serialize_encode(context, context_len, &info);

	// create parameters
	int        mode     = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
		OSSL_PARAM_construct_octet_string(
			OSSL_KDF_PARAM_KEY,
			(void*) secret,
			secret_len
		),
		OSSL_PARAM_construct_octet_string(
			OSSL_KDF_PARAM_INFO,
			info.ptr,
			info.len
		),
		OSSL_PARAM_construct_end(),
	};

	// run KDF
	ctx_set_digest(suite);
	EVP_KDF_derive(ctx, out, length, params);

end:
	if(info.ptr != NULL) vec_free(&info);
	if(real_label != NULL) free(real_label);
	return out;
}

unsigned char* cmls_crypto_DeriveSecret(
	cmls_CipherSuite     suite,
	const unsigned char* secret,
	size_t               secret_len,
	const char*          label
) {
	return cmls_crypto_ExpandWithLabel(
		suite,
		secret,
		secret_len,
		label,
		(unsigned char*) "",
		0,
		cmls_crypto_kdf_nh(suite)
	);
}

unsigned char* cmls_crypto_DeriveTreeSecret(
	cmls_CipherSuite     suite,
	const unsigned char* secret,
	size_t               secret_len,
	const char*          label,
	uint32_t             generation,
	uint16_t             length
) {
	unsigned char context[4] = {0};

	context[0] = generation >> (8 * 3) % 0x100;
	context[1] = generation >> (8 * 2) % 0x100;
	context[2] = generation >> (8 * 1) % 0x100;
	context[3] = generation >> (8 * 0) % 0x100;

	return cmls_crypto_ExpandWithLabel(
		suite,
		secret,
		secret_len,
		label,
		context,
		sizeof(context),
		length
	);
}

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
}
