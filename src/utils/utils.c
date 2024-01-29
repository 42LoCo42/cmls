#include "utils.h"
#include "../crypto/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bytes cstr2bs(const char* cstr) {
	return (bytes){
		.ptr = (unsigned char*) cstr,
		.len = strlen(cstr),
	};
}

char* next_arg(int* argc, char*** argv) {
	if(*argc == 0) return NULL;
	char* res = (*argv)[0];
	(*argc)--;
	(*argv)++;
	return res;
}

int json_opt_int(json_t* value) {
	if(json_is_null(value)) return -1;
	return json_integer_value(value);
}

bytes decode_hex(const char* hex) {
	bytes res = {
		.len = strlen(hex) / 2,
	};
	vec_extend(&res);

	for(size_t i = 0; i < res.len; i++) {
		sscanf(&hex[i * 2], "%2hhx", &res.ptr[i]);
	}
	return res;
}

bool cmls_get_CipherSuite(size_t suite_index_1, void* suite) {
	bool res = false;
	if(suite_index_1 > cmls_max_ciphersuite) {
		warnx("\e[1;31mUnsupported cipher suite: %zu\e[m", suite_index_1);
		goto end;
	}

	cmls_CipherSuite suite_ = cmls_ciphersuites[suite_index_1 - 1];
	if(suite_.skip) {
		warnx("\e[1;31mSkipping cipher suite: %zu\e[m", suite_index_1);
		goto end;
	}

	res                        = true;
	*(cmls_CipherSuite*) suite = suite_;

end:
	return res;
}
