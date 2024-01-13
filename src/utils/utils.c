#include "utils.h"
#include "jansson.h"
#include "string.h"

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
