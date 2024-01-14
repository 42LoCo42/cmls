#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

unsigned char* decode_hex(const char* hex, size_t* len_out) {
	size_t         len = strlen(hex) / 2;
	unsigned char* res = malloc(len);
	if(res == NULL) return res;

	for(size_t i = 0; i < len; i++) {
		sscanf(&hex[i * 2], "%2hhx", &res[i]);
	}
	if(len_out != NULL) *len_out = len;
	return res;
}
