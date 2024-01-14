#ifndef CMLS_UTILS_H
#define CMLS_UTILS_H

#include <jansson.h>

#define Vector(type)                                                           \
	struct {                                                                   \
		type*  ptr;                                                            \
		size_t len;                                                            \
		size_t cap;                                                            \
	}

#define vec_push(vec, val)                                                     \
	{                                                                          \
		vec.len++;                                                             \
		if(vec.len > vec.cap) {                                                \
			vec.cap = (double) vec.cap * 1.5 + 8;                              \
			vec.ptr = reallocarray(vec.ptr, vec.cap, sizeof(*vec.ptr));        \
		}                                                                      \
		vec.ptr[vec.len - 1] = val;                                            \
	}

#define vec_for(vec) for(size_t i = 0; i < vec.len; i++)
#define vec_get(vec, i) vec.ptr[i]

#define vec_free(vec)                                                          \
	{                                                                          \
		free(vec.ptr);                                                         \
		vec.ptr = NULL;                                                        \
		vec.len = 0;                                                           \
		vec.cap = 0;                                                           \
	}

char* next_arg(int* argc, char*** argv);

int json_opt_int(json_t* value);

char* decode_hex(const char* hex, size_t* len);

#endif
