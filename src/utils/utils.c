#include "utils.h"
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
