#include "utils.h"
#include "string.h"

ints readints(char* line) {
	ints res = {0};
	line++; // skip first [

	while(line[0] != 0) {
		char* item = strsep(&line, ",]");

		if(strcmp(item, "null") == 0) {
			vec_push(res, -1);
		} else {
			vec_push(res, atoi(item));
		}
	}

	return res;
}

char* next_arg(int* argc, char*** argv) {
	if(*argc == 0) return NULL;
	char* res = (*argv)[0];
	(*argc)--;
	(*argv)++;
	return res;
}
