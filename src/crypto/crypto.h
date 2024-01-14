#ifndef CMLS_CRYPTO_H
#define CMLS_CRYPTO_H

#include <jansson.h>
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

	int sign_type;
} cmls_CipherSuite;

extern cmls_CipherSuite cmls_ciphersuites[];
extern size_t           cmls_max_ciphersuite;

unsigned char* cmls_crypto_RefHash(
	cmls_CipherSuite     suite,
	const char*          label,
	const unsigned char* data,
	size_t               data_len
);

unsigned char* cmls_crypto_ExpandWithLabel(
	cmls_CipherSuite     suite,
	const unsigned char* secret,
	size_t               secret_len,
	const char*          label,
	const unsigned char* context,
	size_t               context_len,
	uint16_t             length
);

unsigned char* cmls_crypto_DeriveSecret(
	cmls_CipherSuite     suite,
	const unsigned char* secret,
	size_t               secret_len,
	const char*          label
);

unsigned char* cmls_crypto_DeriveTreeSecret(
	cmls_CipherSuite     suite,
	const unsigned char* secret,
	size_t               secret_len,
	const char*          label,
	uint32_t             generation,
	uint16_t             length
);

void cmls_crypto_SignWithLabel(
	cmls_CipherSuite     suite,
	const unsigned char* key,
	size_t               key_len,
	const char*          label,
	const unsigned char* content,
	size_t               content_len,

	unsigned char** sig,
	size_t*         sig_len
);

bool cmls_crypto_VerifyWithLabel(
	cmls_CipherSuite     suite,
	const unsigned char* key,
	size_t               key_len,
	const char*          label,
	const unsigned char* content,
	size_t               content_len,
	const unsigned char* sig,
	size_t               sig_len
);

void cmls_crypto_test(const json_t* entry);

#endif
