#include "serialize.h"
#include "../utils/utils.h"
#include <assert.h>
#include <jansson.h>
#include <stdio.h>

bool cmls_serialize_decode_header(unsigned char* data, size_t* len) {
	switch(data[0] >> 6) {
	case 0:
		*len = data[0];
		break;
	case 1:
		*len = (data[0] & ~0x40) << 8 | data[1];
		break;
	case 2:
		*len = (data[0] & ~0x80) << 24 | data[1] << 16 | data[2] << 8 | data[3];
		break;
	default:
		return false;
	}

	return true;
}

void cmls_serialize_test(json_t* entry) {
	unsigned char* header = (unsigned char*) decode_hex(
		json_string_value(json_object_get(entry, "vlbytes_header")),
		NULL
	);
	size_t length_want = json_integer_value(json_object_get(entry, "length"));
	size_t length_have = 0;

	assert(cmls_serialize_decode_header(header, &length_have));
	assert(length_want == length_have);
	free(header);
}
