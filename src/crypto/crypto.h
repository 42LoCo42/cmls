#ifndef CMLS_CRYPTO_H
#define CMLS_CRYPTO_H

#include <jansson.h>
#include <stddef.h>

char* cmls_crypto_refhash(
	const char*          label,
	const unsigned char* data,
	size_t               data_len
);

void cmls_crypto_test(const json_t* entry);

#endif
