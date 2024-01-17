#include "types.h"

void cmls_Capabilities_free(cmls_Capabilities* value) {
	vec_free(&value->versions);
	vec_free(&value->cipher_suites);
	vec_free(&value->extensions);
	vec_free(&value->proposals);
	vec_free(&value->credentials);
}

void cmls_LeafNode_free(cmls_LeafNode* value) {
	cmls_Capabilities_free(&value->capabilities);
}
