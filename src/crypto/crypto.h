#ifndef CMLS_CRYPTO_H
#define CMLS_CRYPTO_H

#include <jansson.h>

unsigned char* cmls_crypto_RefHash(
	const char*          label,
	const unsigned char* data,
	size_t               data_len
);

unsigned char* cmls_crypto_ExpandWithLabel(
	const unsigned char* secret,
	size_t               secret_len,
	const char*          label,
	const unsigned char* context,
	size_t               context_len,
	uint16_t             length
);

unsigned char* cmls_crypto_DeriveSecret(
	const unsigned char* secret,
	size_t               secret_len,
	const char*          label
);

void cmls_crypto_test(const json_t* entry);

#endif
