#include "crypto.h"
#include "../serialize/serialize.h"
#include "../utils/utils.h"
#include <assert.h>
#include <openssl/sha.h>

unsigned char* cmls_crypto_refhash(
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

	const json_t* ref_hash = json_object_get(entry, "ref_hash");
	const char*   label = json_string_value(json_object_get(ref_hash, "label"));

	size_t               data_len = 0;
	const unsigned char* data     = decode_hex(
        json_string_value(json_object_get(ref_hash, "value")),
        &data_len
    );

	size_t               hash_len  = 0;
	const unsigned char* hash_want = decode_hex(
		json_string_value(json_object_get(ref_hash, "out")),
		&hash_len
	);

	const unsigned char* hash_have = cmls_crypto_refhash(label, data, data_len);
	assert(memcmp(hash_want, hash_have, hash_len) == 0);

	free((char*) hash_have);
	free((char*) hash_want);
	free((char*) data);
}
