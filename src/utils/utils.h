#ifndef CMLS_UTILS_H
#define CMLS_UTILS_H

#include <jansson.h>
#include <string.h>

#ifdef VECTOR_DBG
#define VECTOR_DBG_RUN(x) x
#else
#define VECTOR_DBG_RUN(x)
#endif

#define die(...)                                                               \
	{                                                                          \
		fprintf(stderr, "%s:%d: ", __FILE__, __LINE__);                        \
		warn(__VA_ARGS__);                                                     \
		goto end;                                                              \
	}

#define Vector(type)                                                           \
	struct {                                                                   \
		type*  ptr;                                                            \
		size_t len;                                                            \
		size_t cap;                                                            \
	}

#define vec_extend(vec)                                                        \
	if((vec)->len > (vec)->cap) {                                              \
		(vec)->cap = (double) (vec)->len * 1.5;                                \
		VECTOR_DBG_RUN(                                                        \
			printf("len = %zu, cap = %zu\n", (vec)->len, (vec)->cap)           \
		);                                                                     \
		(vec)->ptr =                                                           \
			reallocarray((vec)->ptr, (vec)->cap, sizeof(*(vec)->ptr));         \
	}

#define vec_push(vec, val)                                                     \
	{                                                                          \
		(vec)->len++;                                                          \
		vec_extend(vec);                                                       \
		(vec)->ptr[(vec)->len - 1] = val;                                      \
	}

#define vec_push_all(vec, data, data_len)                                      \
	{                                                                          \
		(vec)->len += data_len;                                                \
		vec_extend(vec);                                                       \
		memcpy(&(vec)->ptr[(vec)->len - data_len], data, data_len);            \
	}

#define vec_for(vec) for(size_t i = 0; i < (vec)->len; i++)
#define vec_get(vec, i) (vec)->ptr[i]

#define vec_free(vec)                                                          \
	{                                                                          \
		free((vec)->ptr);                                                      \
		(vec)->ptr = NULL;                                                     \
		(vec)->len = 0;                                                        \
		(vec)->cap = 0;                                                        \
	}

typedef Vector(unsigned char) bytes;

char* next_arg(int* argc, char*** argv);

int json_opt_int(json_t* value);

unsigned char* decode_hex(const char* hex, size_t* len);

#endif
