#include "crypto.h"
#include "../serialize/serialize.h"
#include <assert.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/sha.h>

static EVP_KDF_CTX* ctx    = NULL;
static size_t       kdf_nh = 0;

static void __attribute__((constructor)) lib_init() {
	EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	ctx          = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);

	OSSL_PARAM  params[3] = {0};
	OSSL_PARAM* p         = params;

	int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
	*p++     = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
	*p++     = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST,
        SN_sha256,
        strlen(SN_sha256)
    );
	*p = OSSL_PARAM_construct_end();

	EVP_KDF_CTX_set_params(ctx, params);

	kdf_nh = EVP_KDF_CTX_get_kdf_size(ctx);
}

static void __attribute((destructor())) lib_free() {
	EVP_KDF_CTX_free(ctx);
}

unsigned char* cmls_crypto_RefHash(
	const char*          label,
	const unsigned char* data,
	size_t               data_len
) {
	unsigned char* hash = malloc(SHA256_DIGEST_LENGTH);
	if(hash == NULL) return NULL;

	bytes vec = {0};
	cmls_serialize_encode((unsigned char*) label, strlen(label), &vec);
	cmls_serialize_encode(data, data_len, &vec);

	SHA256(vec.ptr, vec.len, hash);
	vec_free(&vec);
	return hash;
}

unsigned char* cmls_crypto_ExpandWithLabel(
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
	OSSL_PARAM  params[4] = {0};
	OSSL_PARAM* p         = params;

	int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
	*p++     = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
	*p++     = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY,
        (void*) secret,
        secret_len
    );
	*p++ = OSSL_PARAM_construct_octet_string(
		OSSL_KDF_PARAM_INFO,
		info.ptr,
		info.len
	);
	*p = OSSL_PARAM_construct_end();

	// run KDF
	EVP_KDF_derive(ctx, out, length, params);

end:
	if(info.ptr != NULL) vec_free(&info);
	if(real_label != NULL) free(real_label);
	return out;
}

unsigned char* cmls_crypto_DeriveSecret(
	const unsigned char* secret,
	size_t               secret_len,
	const char*          label
) {
	return cmls_crypto_ExpandWithLabel(
		secret,
		secret_len,
		label,
		(unsigned char*) "",
		0,
		kdf_nh
	);
}

void cmls_crypto_test(const json_t* entry) {
	int cipher_suite =
		json_integer_value(json_object_get(entry, "cipher_suite"));

	if(cipher_suite > 3) {
		fprintf(
			stderr,
			"\e[1;31mUnsupported cipher suite: %d\e[m\n",
			cipher_suite
		);
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
			cmls_crypto_RefHash(label, data, data_len);
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

		const unsigned char* out_want =
			decode_hex(json_string_value(json_object_get(j, "out")), NULL);

		const unsigned char* out_have =
			cmls_crypto_DeriveSecret(secret, secret_len, label);
		assert(memcmp(out_want, out_have, kdf_nh) == 0);

		free((char*) out_have);
		free((char*) out_want);
		free((char*) secret);
	}
}
