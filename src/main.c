#include "crypto/crypto.h"
#include "serialize/serialize.h"
#include "treemath/treemath.h"
#include <err.h>

static char* ARGV0;

void usage() {
	printf("Usage: %s [test <what>]\n", ARGV0);
	exit(1);
}

void test(char* what) {
	void (*func)(const json_t*) = NULL;
	if(strcmp(what, "treemath") == 0)
		func = cmls_treemath_test;
	else if(strcmp(what, "serialize") == 0)
		func = cmls_serialize_test;
	else if(strcmp(what, "crypto") == 0)
		func = cmls_crypto_test;
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
	} else if(strcmp(mode, "foo") == 0) {
		unsigned char* priv = NULL;
		EVP_PKEY*      pkey = NULL;

		size_t priv_len = 0;
		priv            = decode_hex(
            "a2f640dd5005fcad6adb8e9bd8b60d70946bb802e1e788307929fdac81e1ec74",
            &priv_len
        );
		if(priv == NULL) die("decode priv");

		pkey = cmls_crypto_mkKey(cmls_ciphersuites[0], priv, priv_len);
		if(pkey == NULL) die("mkKey");

		printf("%d\n", EVP_PKEY_get_size(pkey));

	end:
		if(pkey != NULL) EVP_PKEY_free(pkey);
		if(priv != NULL) free(priv);
	}

	return 0;
}
