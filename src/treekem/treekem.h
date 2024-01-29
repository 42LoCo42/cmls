#ifndef CMLS_TREEKEM_H
#define CMLS_TREEKEM_H

#include "../crypto/crypto.h"
#include "../utils/utils.h"
#include <jansson.h>

bytes cmls_treekem_derive_path_secret(
	cmls_CipherSuite suite,
	bytes            path_secret
);

bytes cmls_treekem_derive_node_secret(
	cmls_CipherSuite suite,
	bytes            path_secret
);

EVP_PKEY*
cmls_treekem_derive_keypair(cmls_CipherSuite suite, bytes node_secret);

void cmls_treekem_test(const json_t* entry);

#endif
