#include <err.h>
#include <jansson.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "treemath/treemath.h"
#include "utils/utils.h"

#define die(...)                                                               \
	{                                                                          \
		fprintf(stderr, "%s:%d: ", __FILE__, __LINE__);                        \
		warn(__VA_ARGS__);                                                     \
		goto end;                                                              \
	}

static char* ARGV0;

void usage() {
	printf("Usage: %s [test <what>]\n", ARGV0);
	exit(1);
}

void test(char* what) {
	void (*func)(json_t*) = NULL;
	if(strcmp(what, "treemath") == 0) func = cmls_treemath_test;
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
	}

	return 0;
}
