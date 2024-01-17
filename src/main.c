#include "crypto/crypto.h"
#include "encoding/encoding.h"
#include "serialize/serialize.h"
#include "treemath/treemath.h"

static char* ARGV0;

void usage() {
	printf("Usage: %s <test <what> | testall>\n", ARGV0);
	exit(1);
}

void test(char* what) {
	void (*func)(const json_t*) = NULL;

	if(strcmp(what, "crypto") == 0)
		func = cmls_crypto_test;
	else if(strcmp(what, "serialize") == 0)
		func = cmls_serialize_test;
	else if(strcmp(what, "treemath") == 0)
		func = cmls_treemath_test;

	if(func == NULL) usage();

	printf("\e[1;33mRunning test %s...\e[m\n", what);

	char*   path = NULL;
	FILE*   file = NULL;
	json_t* root = NULL;

	if(asprintf(&path, "src/%s/test.json", what) < 0) die("asprintf");

	file = fopen(path, "r");
	if(file == NULL) die("fopen %s", path);

	json_error_t error = {0};
	root               = json_loadf(file, 0, &error);
	if(root == NULL)
		die("json load: %s:%d:%d: %s",
		    error.source,
		    error.line,
		    error.column,
		    error.text);

	for(size_t i = 0; i < json_array_size(root); i++) {
		func(json_array_get(root, i));
	}

end:
	if(root != NULL) json_decref(root);
	if(file != NULL) fclose(file);
	if(path != NULL) free(path);
}

int main(int argc, char** argv) {
	ARGV0 = next_arg(&argc, &argv);

	char* mode = next_arg(&argc, &argv);
	if(mode == NULL) usage();

	if(strcmp(mode, "test") == 0) {
		char* what = next_arg(&argc, &argv);
		if(what == NULL) usage();
		test(what);
	} else if(strcmp(mode, "testall") == 0) {
		test("crypto");
		test("serialize");
		test("treemath");
	} else {
		bytes tree_ = decode_hex(
			"41da010120c929637bda524adad04ac85cf8ab7164d9cd88139aef5c9f71579027"
			"07c3fb5820c4c1595a92bc2fe9413a0eb6484a106159300bbd27d9f69c8287bff4"
			"c812685100012064f3832198d0541bb38e744801075164e81371c4952ad36e2a41"
			"c8fcac593f930200010c000100020003000400050006000004000100020320be6b"
			"0e33b576ab16727c86317eee6b8bbc20b641440f1f55ed68a4861b6746f7004040"
			"4007c2a631b8a394f6cb8704b1cbbe2e149241ca32f316ffc6f8a541521b0a298d"
			"c0239d0ec0e8ab77f3c39b5810da1815d3a83dd4797d0ea5a0488718b8af020102"
			"2029eb3645264612282039eb7ddb095a780f39b1904a9613aaad568642a4b9b204"
			"0000010120d17b7296c1ac920c635574c84ee59f11c43bf534f4135225dbf1ac36"
			"0e4629092018fb8325dea495db27f818b49f80fbe1e41bd07e8f56e519325b0fdf"
			"5f34a69f0001209461d191779dc58ef19be7df44f74252e5fefab3e0b7e04d05e8"
			"66138390325d0200010c0001000200030004000500060000040001000201000000"
			"0000000000ffffffffffffffff0040405ca8f99de58c59bc29c4d7b5bbc489ca7a"
			"62a8971d5944080940cf14d6795443a20cd96c290a67b59c28a53e9e9795ac9f21"
			"cbb257ca333e75e72e5582ca8e0f"
		);

		bytes tree  = tree_;
		bytes inner = cmls_dec_vector(&tree);
		printf("node found: %d\n", cmls_dec_optional(&inner));
		printf("of type: %d\n", cmls_dec_NodeType(&inner));

		cmls_LeafNode node = cmls_dec_LeafNode(&inner);
		printf("encryption key: %zu\n", node.encryption_key.len);
		printf("signature key: %zu\n", node.signature_key.len);
		printf(
			"credential type: %d, identity: %zu\n",
			node.credential.credential_type,
			node.credential.data.identity.len
		);

		for(size_t i = 0; i < node.capabilities.versions.len; i++) {
			printf("version: %d\n", node.capabilities.versions.ptr[i]);
		}

		for(size_t i = 0; i < node.capabilities.cipher_suites.len; i++) {
			printf(
				"cipher suite: %d\n",
				node.capabilities.cipher_suites.ptr[i]
			);
		}

		for(size_t i = 0; i < node.capabilities.extensions.len; i++) {
			printf("extension: %d\n", node.capabilities.extensions.ptr[i]);
		}

		for(size_t i = 0; i < node.capabilities.proposals.len; i++) {
			printf("proposal: %d\n", node.capabilities.proposals.ptr[i]);
		}

		for(size_t i = 0; i < node.capabilities.credentials.len; i++) {
			printf("credential: %d\n", node.capabilities.credentials.ptr[i]);
		}

		printf("leaf node source: %d\n", node.leaf_node_source);
		printf("parent hash: %zu\n", node.data.parent_hash.len);

		printf("extensions: %zu\n", node.extensions.len);
		printf("signature: %zu\n", node.signature.len);

		vec_free(&node.capabilities.credentials);
		vec_free(&node.capabilities.proposals);
		vec_free(&node.capabilities.extensions);
		vec_free(&node.capabilities.cipher_suites);
		vec_free(&node.capabilities.versions);
		vec_free(&tree_);
	}

	return 0;
}
