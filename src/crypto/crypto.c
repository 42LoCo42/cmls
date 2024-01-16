#include "crypto.h"
#include "../serialize/serialize.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

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

EVP_PKEY*
cmls_crypto_mkKey(cmls_CipherSuite suite, bytes data, mkkey_flags flags) {
	EVP_PKEY_CTX* pkey_ctx = NULL;
	EVP_PKEY*     pkey     = NULL;

	int key_type =
		flags & MKKEY_HPKE ? suite.key_hpke_type : suite.key_sign_type;
	pkey_ctx = EVP_PKEY_CTX_new_id(key_type, NULL);
	if(pkey_ctx == NULL) odie("pkey ctx init");

	OSSL_PARAM  params[3] = {0};
	OSSL_PARAM* p         = params;

	if(suite.key_sign_type == EVP_PKEY_EC) {
		*p++ = OSSL_PARAM_construct_utf8_string(
			OSSL_PKEY_PARAM_GROUP_NAME,
			(char*) suite.key_group,
			strlen(suite.key_group)
		);
	}

	typedef OSSL_PARAM (*construct_t)(const char* key, void* buf, size_t len);
	construct_t construct =
		flags & MKKEY_PUBLIC || suite.key_sign_type != EVP_PKEY_EC
			? OSSL_PARAM_construct_octet_string
			: (construct_t) OSSL_PARAM_construct_BN;

	const char* key = flags & MKKEY_PUBLIC ? OSSL_PKEY_PARAM_PUB_KEY
	                                       : OSSL_PKEY_PARAM_PRIV_KEY;

	*p++ = construct(key, data.ptr, data.len);
	*p   = OSSL_PARAM_construct_end();

	if(EVP_PKEY_fromdata_init(pkey_ctx) <= 0) odie("fromdata init");
	if(EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
		odie("fromdata");

end:
	if(pkey_ctx != NULL) EVP_PKEY_CTX_free(pkey_ctx);
	return pkey;
}

void cmls_crypto_RLC(const char* label, bytes content, bytes* vec) {
	char* real_label = NULL;
	if(asprintf(&real_label, "MLS 1.0 %s", label) < 0)
		die("asprintf real label");

	cmls_serialize_encode(cstr2bs(real_label), vec);
	cmls_serialize_encode(content, vec);

end:
	if(real_label != NULL) free(real_label);
}

bytes cmls_crypto_RefHash(
	cmls_CipherSuite suite,
	const char*      label,
	bytes            value
) {
	bytes hash = {.len = suite.hash_length};
	vec_extend(&hash);

	bytes vec = {0};
	cmls_serialize_encode(cstr2bs(label), &vec);
	cmls_serialize_encode(value, &vec);

	suite.hash(vec.ptr, vec.len, hash.ptr);
	vec_free(&vec);
	return hash;
}

bytes cmls_crypto_ExpandWithLabel(
	cmls_CipherSuite suite,
	bytes            secret,
	const char*      label,
	bytes            context,
	uint16_t         length
) {
	bytes out = {.len = length};
	vec_extend(&out);

	// create KDFLabel
	bytes info = {0};
	vec_push(&info, length >> (8 * 1));
	vec_push(&info, length >> (8 * 0));
	cmls_crypto_RLC(label, context, &info);

	// create parameters
	int        mode     = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
		OSSL_PARAM_construct_octet_string(
			OSSL_KDF_PARAM_KEY,
			secret.ptr,
			secret.len
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
	EVP_KDF_derive(kdf_ctx, out.ptr, length, params);

	if(info.ptr != NULL) vec_free(&info);
	return out;
}

bytes cmls_crypto_DeriveSecret(
	cmls_CipherSuite suite,
	bytes            secret,
	const char*      label
) {
	return cmls_crypto_ExpandWithLabel(
		suite,
		secret,
		label,
		(bytes){0},
		cmls_crypto_kdf_nh(suite)
	);
}

bytes cmls_crypto_DeriveTreeSecret(
	cmls_CipherSuite suite,
	bytes            secret,
	const char*      label,
	uint32_t         generation,
	uint16_t         length
) {
	unsigned char data[4] = {0};

	data[0] = generation >> (8 * 3) % 0x100;
	data[1] = generation >> (8 * 2) % 0x100;
	data[2] = generation >> (8 * 1) % 0x100;
	data[3] = generation >> (8 * 0) % 0x100;

	bytes context = {.ptr = data, .len = sizeof(data)};
	return cmls_crypto_ExpandWithLabel(suite, secret, label, context, length);
}

bytes cmls_crypto_SignWithLabel(
	EVP_PKEY*   secret_key,
	const char* label,
	bytes       content
) {
	EVP_MD_CTX_reset(md_ctx);

	bytes msg = {0};
	bytes sig = {0};

	// create message
	cmls_crypto_RLC(label, content, &msg);

	sig.len = EVP_PKEY_get_size(secret_key);
	vec_extend(&sig);

	// create signature
	if(EVP_DigestSignInit_ex(
		   md_ctx,
		   NULL,
		   NULL,
		   NULL,
		   NULL,
		   secret_key,
		   NULL
	   ) <= 0)
		odie("DigestSign init");
	if(EVP_DigestSign(md_ctx, sig.ptr, &sig.len, msg.ptr, msg.len) <= 0)
		odie("DigestSign");

end:
	if(msg.ptr != NULL) vec_free(&msg);
	return sig;
}

bool cmls_crypto_VerifyWithLabel(
	EVP_PKEY*   public_key,
	const char* label,
	bytes       content,
	bytes       sig
) {
	EVP_MD_CTX_reset(md_ctx);

	bytes msg = {0};
	bool  ok  = false;

	// create message
	cmls_crypto_RLC(label, content, &msg);

	// perform verification
	if(EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, public_key) <= 0)
		odie("DigestVerify init");
	ok = EVP_DigestVerify(md_ctx, sig.ptr, sig.len, msg.ptr, msg.len);

end:
	if(msg.ptr != NULL) vec_free(&msg);
	return ok;
}

void cmls_crypto_EncryptWithLabel(
	cmls_CipherSuite suite,
	bytes            public_key,
	const char*      label,
	bytes            context,
	bytes            plaintext,

	bytes* kem_output,
	bytes* ciphertext
) {
	OSSL_HPKE_CTX* ctx  = NULL;
	bytes          info = {0};

	cmls_crypto_RLC(label, context, &info);

	kem_output->len = OSSL_HPKE_get_public_encap_size(suite.hpke_suite);
	vec_extend(kem_output);

	ciphertext->len = plaintext.len + 16; // found via testing
	vec_extend(ciphertext);

	ctx = OSSL_HPKE_CTX_new(
		OSSL_HPKE_MODE_BASE,
		suite.hpke_suite,
		OSSL_HPKE_ROLE_SENDER,
		NULL,
		NULL
	);
	if(ctx == NULL) odie("HPKE ctx init");

	if(OSSL_HPKE_encap(
		   ctx,
		   kem_output->ptr,
		   &kem_output->len,
		   public_key.ptr,
		   public_key.len,
		   info.ptr,
		   info.len
	   ) <= 0)
		odie("HPKE encap");

	if(OSSL_HPKE_seal(
		   ctx,
		   ciphertext->ptr,
		   &ciphertext->len,
		   NULL,
		   0,
		   plaintext.ptr,
		   plaintext.len
	   ) <= 0)
		odie("HPKE seal");

end:
	if(info.ptr != NULL) vec_free(&info);
	if(ctx != NULL) OSSL_HPKE_CTX_free(ctx);
}

bytes cmls_crypto_DecryptWithLabel(
	cmls_CipherSuite suite,
	EVP_PKEY*        secret_key,
	const char*      label,
	bytes            context,
	bytes            kem_output,
	bytes            ciphertext
) {
	OSSL_HPKE_CTX* ctx       = NULL;
	bytes          info      = {0};
	bytes          plaintext = {.len = ciphertext.len};

	cmls_crypto_RLC(label, context, &info);
	vec_extend(&plaintext);

	ctx = OSSL_HPKE_CTX_new(
		OSSL_HPKE_MODE_BASE,
		suite.hpke_suite,
		OSSL_HPKE_ROLE_RECEIVER,
		NULL,
		NULL
	);
	if(ctx == NULL) odie("HPKE ctx init");

	if(OSSL_HPKE_decap(
		   ctx,
		   kem_output.ptr,
		   kem_output.len,
		   secret_key,
		   info.ptr,
		   info.len
	   ) <= 0)
		odie("HPKE decap");

	if(OSSL_HPKE_open(
		   ctx,
		   plaintext.ptr,
		   &plaintext.len,
		   NULL,
		   0,
		   ciphertext.ptr,
		   ciphertext.len
	   ) <= 0)
		odie("HPKE open");

end:
	if(info.ptr != NULL) vec_free(&info);
	if(ctx != NULL) OSSL_HPKE_CTX_free(ctx);
	return plaintext;
}
