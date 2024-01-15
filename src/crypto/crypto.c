#include "crypto.h"
#include "../serialize/serialize.h"
#include "openssl/params.h"
#include <err.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <stdio.h>

#define odie(...)                                                              \
	{                                                                          \
		ERR_print_errors_fp(stderr);                                           \
		die(__VA_ARGS__);                                                      \
	}

cmls_CipherSuite cmls_ciphersuites[] = {
	{
		.hash        = SHA256,
		.hash_name   = SN_sha256,
		.hash_length = SHA256_DIGEST_LENGTH,

		.key_type = EVP_PKEY_ED25519,
	},
	{
		.skip        = true,
		.hash        = SHA256,
		.hash_name   = SN_sha256,
		.hash_length = SHA256_DIGEST_LENGTH,

		.key_type  = EVP_PKEY_EC,
		.key_group = "prime256v1",
	},
	{
		.hash        = SHA256,
		.hash_name   = SN_sha256,
		.hash_length = SHA256_DIGEST_LENGTH,

		.key_type = EVP_PKEY_ED25519,
	},
	{
		.hash        = SHA512,
		.hash_name   = SN_sha512,
		.hash_length = SHA512_DIGEST_LENGTH,

		.key_type = EVP_PKEY_ED448,
	},
	{
		.skip        = true,
		.hash        = SHA512,
		.hash_name   = SN_sha512,
		.hash_length = SHA512_DIGEST_LENGTH,

		.key_type  = EVP_PKEY_EC,
		.key_group = "secp521r1",
	},
	{
		.hash        = SHA512,
		.hash_name   = SN_sha512,
		.hash_length = SHA512_DIGEST_LENGTH,

		.key_type = EVP_PKEY_ED448,
	},
	{
		.skip        = true,
		.hash        = SHA384,
		.hash_name   = SN_sha384,
		.hash_length = SHA384_DIGEST_LENGTH,

		.key_type  = EVP_PKEY_EC,
		.key_group = "secp384r1",
	},
};

size_t cmls_max_ciphersuite =
	sizeof(cmls_ciphersuites) / sizeof(cmls_ciphersuites[0]);

static EVP_KDF_CTX* kdf_ctx = NULL;
static EVP_MD_CTX*  md_ctx  = NULL;

static void __attribute__((constructor)) lib_init() {
	EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	kdf_ctx      = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);

	md_ctx = EVP_MD_CTX_new();
}

static void __attribute((destructor())) lib_free() {
	EVP_KDF_CTX_free(kdf_ctx);
	EVP_MD_CTX_free(md_ctx);
}

static void ctx_set_digest(cmls_CipherSuite suite) {
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string(
			OSSL_KDF_PARAM_DIGEST,
			suite.hash_name,
			strlen(suite.hash_name)
		),
		OSSL_PARAM_END,
	};
	EVP_KDF_CTX_set_params(kdf_ctx, params);
}

static size_t cmls_crypto_kdf_nh(cmls_CipherSuite suite) {
	ctx_set_digest(suite);
	int        mode     = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
		OSSL_PARAM_END,
	};
	EVP_KDF_CTX_set_params(kdf_ctx, params);
	return EVP_KDF_CTX_get_kdf_size(kdf_ctx);
}

EVP_PKEY* cmls_crypto_mkKey(
	cmls_CipherSuite     suite,
	const unsigned char* priv,
	size_t               priv_len
) {
	EVP_PKEY_CTX* pkey_ctx = NULL;
	EVP_PKEY*     pkey     = NULL;

	pkey_ctx = EVP_PKEY_CTX_new_id(suite.key_type, NULL);
	if(pkey_ctx == NULL) odie("pkey ctx init");

	OSSL_PARAM  params[3] = {0};
	OSSL_PARAM* p         = params;

	*p++ = OSSL_PARAM_construct_BN(
		OSSL_PKEY_PARAM_PRIV_KEY,
		(unsigned char*) priv,
		priv_len
	);

	if(suite.key_group != NULL) {
		*p++ = OSSL_PARAM_construct_utf8_string(
			OSSL_PKEY_PARAM_GROUP_NAME,
			(char*) suite.key_group,
			strlen(suite.key_group)
		);
	}

	*p = OSSL_PARAM_construct_end();

	if(EVP_PKEY_fromdata_init(pkey_ctx) <= 0) odie("fromdata init");
	if(EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
		odie("fromdata");

end:
	if(pkey_ctx != NULL) EVP_PKEY_CTX_free(pkey_ctx);
	return pkey;
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
		OSSL_PARAM_END,
	};

	// run KDF
	ctx_set_digest(suite);
	EVP_KDF_derive(kdf_ctx, out, length, params);

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

static bytes mkSignContent(
	const char*          label,
	const unsigned char* content,
	size_t               content_len
) {
	char* real_label = NULL;
	bytes msg        = {0};

	if(asprintf(&real_label, "MLS 1.0 %s", label) < 0) goto end;
	cmls_serialize_encode(
		(unsigned char*) real_label,
		strlen(real_label),
		&msg
	);
	cmls_serialize_encode(content, content_len, &msg);

end:
	if(real_label != NULL) free(real_label);
	return msg;
}

void cmls_crypto_SignWithLabel(
	cmls_CipherSuite     suite,
	const unsigned char* key,
	size_t               key_len,
	const char*          label,
	const unsigned char* content,
	size_t               content_len,
	unsigned char**      sig,
	size_t*              sig_len
) {
	EVP_MD_CTX_reset(md_ctx);

	bytes          msg     = {0};
	EVP_PKEY*      pkey    = NULL;
	unsigned char* out     = NULL;
	size_t         out_len = 0;

	// create message
	msg = mkSignContent(label, content, content_len);

	// create key
	pkey = EVP_PKEY_new_raw_private_key(suite.key_type, NULL, key, key_len);
	if(pkey == NULL) odie("pkey init");

	out_len = EVP_PKEY_get_size(pkey);
	if((out = OPENSSL_zalloc(out_len)) == NULL) odie("alloc sig");

	// create signature
	if(EVP_DigestSignInit_ex(md_ctx, NULL, NULL, NULL, NULL, pkey, NULL) <= 0)
		odie("DigestSign init");
	if(EVP_DigestSign(md_ctx, out, &out_len, msg.ptr, msg.len) <= 0)
		odie("DigestSign");

end:
	if(pkey != NULL) EVP_PKEY_free(pkey);
	if(msg.ptr != NULL) vec_free(&msg);
	*sig     = out;
	*sig_len = out_len;
}

bool cmls_crypto_VerifyWithLabel(
	cmls_CipherSuite     suite,
	const unsigned char* key,
	size_t               key_len,
	const char*          label,
	const unsigned char* content,
	size_t               content_len,
	const unsigned char* sig,
	size_t               sig_len
) {
	EVP_MD_CTX_reset(md_ctx);

	bytes     msg  = {0};
	EVP_PKEY* pkey = NULL;
	bool      ok   = false;

	// create message
	msg = mkSignContent(label, content, content_len);

	// create key
	if((pkey = EVP_PKEY_new_raw_public_key(suite.key_type, NULL, key, key_len)
	   ) == NULL)
		odie("pkey init");

	// perform verification
	if(EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) <= 0)
		odie("DigestVerify init");
	ok = EVP_DigestVerify(md_ctx, sig, sig_len, msg.ptr, msg.len);

end:
	if(pkey != NULL) EVP_PKEY_free(pkey);
	if(msg.ptr != NULL) vec_free(&msg);
	return ok;
}
