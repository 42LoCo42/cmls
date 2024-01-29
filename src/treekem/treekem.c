#include "../crypto/crypto.h"
#include "../encoding/encoding.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "openssl/params.h"
#include <assert.h>

bytes cmls_treekem_derive_path_secret(
	cmls_CipherSuite suite,
	bytes            path_secret
) {
	return cmls_crypto_DeriveSecret(suite, path_secret, "path");
}

bytes cmls_treekem_derive_node_secret(
	cmls_CipherSuite suite,
	bytes            path_secret
) {
	return cmls_crypto_DeriveSecret(suite, path_secret, "node");
}

EVP_PKEY*
cmls_treekem_derive_keypair(cmls_CipherSuite suite, bytes node_secret) {
	EVP_PKEY_CTX* ctx = NULL;
	EVP_PKEY*     key = NULL;

	if((ctx = EVP_PKEY_CTX_new_id(suite.key_hpke_type, NULL)) == NULL)
		odie("keygen ctx init");
	if(EVP_PKEY_keygen_init(ctx) <= 0) odie("keygen init");
	if(EVP_PKEY_CTX_set_params(
		   ctx,
		   (OSSL_PARAM[]){
			   OSSL_PARAM_construct_octet_string(
				   OSSL_PKEY_PARAM_DHKEM_IKM,
				   node_secret.ptr,
				   node_secret.len
			   ),
			   OSSL_PARAM_END,
		   }
	   ) <= 0)
		odie("keygen set IKM");

	if(EVP_PKEY_keygen(ctx, &key) <= 0) odie("keygen");

end:
	if(ctx != NULL) EVP_PKEY_CTX_free(ctx);
	return key;
}

void cmls_treekem_test(const json_t* entry) {
	cmls_CipherSuite suite = {0};
	if(!cmls_get_CipherSuite(
		   json_integer_value(json_object_get(entry, "cipher_suite")),
		   &suite
	   ))
		return;

	bytes tree_data_ =
		decode_hex(json_string_value(json_object_get(entry, "ratchet_tree")));
	bytes tree_data = tree_data_;

	cmls_RatchetTree tree = cmls_dec_RatchetTree(&tree_data);

	const json_t* leaves_private = json_object_get(entry, "leaves_private");
	for(size_t i = 0; i < json_array_size(leaves_private); i++) {
		json_t* leaf_private = json_array_get(leaves_private, i);
		json_t* path_secrets = json_object_get(leaf_private, "path_secrets");
		for(size_t i = 0; i < json_array_size(path_secrets); i++) {
			json_t* entry = json_array_get(path_secrets, i);

			size_t node = json_integer_value(json_object_get(entry, "node"));

			bytes path_secret = decode_hex(
				json_string_value(json_object_get(entry, "path_secret"))
			);

			bytes node_secret =
				cmls_treekem_derive_node_secret(suite, path_secret);
			EVP_PKEY* key = cmls_treekem_derive_keypair(suite, node_secret);

			bytes key_want = tree.ptr[node].data.parent_node.encryption_key;
			bytes key_have = {.len = key_want.len};
			vec_extend(&key_have);

			if(EVP_PKEY_get_raw_public_key(key, key_have.ptr, &key_have.len) <=
			   0)
				odie("key get private");

			assert(key_want.len == key_have.len);
			assert(memcmp(key_want.ptr, key_have.ptr, key_want.len) == 0);

			vec_free(&key_have);
			EVP_PKEY_free(key);
			vec_free(&node_secret);
			vec_free(&path_secret);
		}
	}

end:

	cmls_RatchetTree_free(&tree);
	vec_free(&tree_data_);
}
