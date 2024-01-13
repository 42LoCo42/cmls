#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "treemath/treemath.h"
#include "utils/utils.h"

void usage(const char* program) {
	printf("Usage: %s [test <what>]\n", program);
	exit(1);
}

int main(int argc, char** argv) {
	char* program = next_arg(&argc, &argv);

	char* mode = next_arg(&argc, &argv);
	if(mode == NULL) usage(program);

	if(strcmp(mode, "test") == 0) {
		char* what = next_arg(&argc, &argv);
		if(what == NULL) usage(program);

		void (*func)(char*) = NULL;
		if(strcmp(what, "treemath") == 0) func = cmls_treemath_test;
		if(func == NULL) usage(program);

		char*  line = NULL;
		size_t n    = 0;

		printf("\e[1;33mRunning test %s...\e[m\n", what);
		for(;;) {
			ssize_t len = getline(&line, &n, stdin);
			if(len < 0) break;
			func(line);
		}

		free(line);
	}

	return 0;
}
