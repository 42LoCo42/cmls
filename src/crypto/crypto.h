#ifndef CMLS_CRYPTO_H
#define CMLS_CRYPTO_H

#include "../utils/utils.h"
#include <jansson.h>
#include <openssl/hpke.h>
#include <stdbool.h>

typedef struct {
	bool skip;

	unsigned char* (*hash)(
		const unsigned char* data,
		size_t               len,
		unsigned char*       out
	);
	char*  hash_name;
	size_t hash_length;

	int         key_sign_type;
	int         key_hpke_type;
	const char* key_group;

	OSSL_HPKE_SUITE hpke_suite;
} cmls_CipherSuite;

extern cmls_CipherSuite cmls_ciphersuites[];
extern size_t           cmls_max_ciphersuite;

typedef enum {
	MKKEY_SECRET = 0b00,
	MKKEY_PUBLIC = 0b01,

	MKKEY_SIGN = 0b00,
	MKKEY_HPKE = 0b10,
} mkkey_flags;

EVP_PKEY*
cmls_crypto_mkKey(cmls_CipherSuite suite, bytes data, mkkey_flags flags);

void cmls_crypto_RLC(const char* label, bytes content, bytes* vec);

bytes cmls_crypto_RefHash(
	cmls_CipherSuite suite,
	const char*      label,
	bytes            value
);

bytes cmls_crypto_ExpandWithLabel(
	cmls_CipherSuite suite,
	bytes            secret,
	const char*      label,
	bytes            context,
	uint16_t         length
);

bytes cmls_crypto_DeriveSecret(
	cmls_CipherSuite suite,
	bytes            secret,
	const char*      label
);

bytes cmls_crypto_DeriveTreeSecret(
	cmls_CipherSuite suite,
	bytes            secret,
	const char*      label,
	uint32_t         generation,
	uint16_t         length
);

bytes cmls_crypto_SignWithLabel(
	EVP_PKEY*   secret_key,
	const char* label,
	bytes       content
);

bool cmls_crypto_VerifyWithLabel(
	EVP_PKEY*   public_key,
	const char* label,
	bytes       content,
	bytes       sig
);

void cmls_crypto_EncryptWithLabel(
	cmls_CipherSuite suite,
	bytes            public_key,
	const char*      label,
	bytes            context,
	bytes            plaintext,

	bytes* kem_output,
	bytes* ciphertext
);

bytes cmls_crypto_DecryptWithLabel(
	cmls_CipherSuite suite,
	EVP_PKEY*        secret_key,
	const char*      label,
	bytes            context,
	bytes            kem_output,
	bytes            ciphertext
);

void cmls_crypto_test(const json_t* entry);

#endif
