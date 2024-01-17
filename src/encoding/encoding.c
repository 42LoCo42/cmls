#include "encoding.h"
#include <assert.h>

uint8_t cmls_dec_uint8(bytes* data) {
	uint8_t res = data->ptr[0];
	data->ptr++;
	return res;
}

uint16_t cmls_dec_uint16(bytes* data) {
	union {
		uint16_t res;
		uint8_t  arr[2];
	} x;

	memcpy(x.arr, data->ptr, sizeof(x.res));
	data->ptr += sizeof(x.res);
	return be16toh(x.res);
}

uint32_t cmls_dec_uint32(bytes* data) {
	union {
		uint32_t res;
		uint8_t  arr[4];
	} x;

	memcpy(x.arr, data->ptr, sizeof(x.res));
	data->ptr += sizeof(x.res);
	return be32toh(x.res);
}

uint64_t cmls_dec_uint64(bytes* data) {
	union {
		uint64_t res;
		uint8_t  arr[8];
	} x;

	memcpy(x.arr, data->ptr, sizeof(x.res));
	data->ptr += sizeof(x.res);
	return be64toh(x.res);
}

void cmls_enc_optional(bytes* data, bool value) {
	vec_push(data, value);
}

cmls_Optional cmls_dec_optional(bytes* data) {
	cmls_Optional res;
	switch(data->ptr[0]) {
	case 0:
		res = OPTIONAL_NO;
		break;
	case 1:
		res = OPTIONAL_OK;
		break;
	default:
		res = OPTIONAL_ERR;
	}

	data->ptr++;
	return res;
}

void cmls_enc_vector_header(bytes* data, size_t value) {
	if(value < 0x40) {
		vec_push(data, value);
	} else if(value < 0x4000) {
		vec_push(data, value >> (8 * 1) | 0x40);
		vec_push(data, value >> (8 * 0) % 0x100);
	} else if(value < 0x40000000) {
		vec_push(data, value >> (8 * 3) | 0x80);
		vec_push(data, value >> (8 * 2) % 0x100);
		vec_push(data, value >> (8 * 1) % 0x100);
		vec_push(data, value >> (8 * 0) % 0x100);
	}
}

ssize_t cmls_dec_vector_header(bytes* data) {
	ssize_t        res = 0;
	unsigned char* ptr = data->ptr;

	switch(ptr[0] >> 6) {
	case 0:
		res = ptr[0];
		data->ptr += 1;
		break;
	case 1:
		res = (ptr[0] & ~0x40) << 8 | ptr[1];
		data->ptr += 2;
		break;
	case 2:
		res = (ptr[0] & ~0x80) << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
		data->ptr += 4;
		break;
	default:
		res = -1;
	}

	return res;
}

void cmls_enc_vector(bytes* data, bytes value) {
	cmls_enc_vector_header(data, value.len);
	vec_push_all(data, value.ptr, value.len);
}

bytes cmls_dec_vector(bytes* data) {
	ssize_t len = cmls_dec_vector_header(data);
	if(len < 0) return (bytes){0};

	unsigned char* ptr = data->ptr;
	data->ptr += len;

	return (bytes){
		.ptr = ptr,
		.len = len,
	};
}

#define define_enum_dec_(type, size)                                           \
	cmls_##type cmls_dec_##type(bytes* data) {                                 \
		cmls_##type res = cmls_dec_##size(data);                               \
		if(res < 0 || res >= type##_FINAL) res = -1;                           \
		return res;                                                            \
	}

#define define_enum_decI(type, size)                                           \
	define_enum_dec_(type, size);                                              \
	static size_t type##_inc = sizeof(size##_t)

define_enum_dec_(NodeType, uint8);
define_enum_decI(ProtocolVersion, uint16);
define_enum_decI(CipherSuiteType, uint16);
define_enum_decI(ExtensionType, uint16);
define_enum_decI(ProposalType, uint16);
define_enum_decI(CredentialType, uint16);
define_enum_dec_(LeafNodeSource, uint8);

#undef define_enum_dec

cmls_Credential cmls_dec_Credential(bytes* data) {
	cmls_Credential res = {0};
	res.credential_type = cmls_dec_CredentialType(data);
	switch(res.credential_type) {
	case CredentialType_Basic:
		res.data.identity = cmls_dec_vector(data);
		break;
	default:
		assert("TODO: not implemented" && false);
	}
	return res;
}

#define vector_field(name, type)                                               \
	{                                                                          \
		bytes name = cmls_dec_vector(data);                                    \
		for(size_t i = 0; i < name.len; i += type##_inc) {                     \
			vec_push(&res.name, cmls_dec_##type(&name));                       \
		}                                                                      \
	}

cmls_Capabilities cmls_dec_Capabilities(bytes* data) {
	cmls_Capabilities res = {0};

	vector_field(versions, ProtocolVersion);
	vector_field(cipher_suites, CipherSuiteType);
	vector_field(extensions, ExtensionType);
	vector_field(proposals, ProposalType);
	vector_field(credentials, CredentialType);

	return res;
}

cmls_LifeTime cmls_dec_LifeTime(bytes* data) {
	cmls_LifeTime res = {0};
	res.not_before    = cmls_dec_uint64(data);
	res.not_after     = cmls_dec_uint64(data);
	return res;
}

cmls_Extension cmls_dec_Extension(bytes* data) {
	cmls_Extension res = {0};
	res.extension_type = cmls_dec_ExtensionType(data);
	res.extension_data = cmls_dec_vector(data);
	return res;
}

static size_t Extension_inc = sizeof(cmls_Extension);

cmls_LeafNode cmls_dec_LeafNode(bytes* data) {
	cmls_LeafNode res  = {0};
	res.encryption_key = cmls_dec_vector(data);
	res.signature_key  = cmls_dec_vector(data);
	res.credential     = cmls_dec_Credential(data);
	res.capabilities   = cmls_dec_Capabilities(data);

	res.leaf_node_source = cmls_dec_LeafNodeSource(data);
	switch(res.leaf_node_source) {
	case LeafNodeSource_KeyPackage:
		res.data.lifetime = cmls_dec_LifeTime(data);
		break;
	case LeafNodeSource_Update:
		break;
	case LeafNodeSource_Commmit:
		res.data.parent_hash = cmls_dec_vector(data);
		break;
	default:
		assert("TODO: IMPOSSIBLE" && false);
	}

	vector_field(extensions, Extension);
	res.signature = cmls_dec_vector(data);
	return res;
}

void cmls_encoding_test(const json_t* entry) {
	bytes header_want =
		decode_hex(json_string_value(json_object_get(entry, "vlbytes_header")));
	bytes header_ptr = header_want;

	ssize_t length_want = json_integer_value(json_object_get(entry, "length"));
	ssize_t length_have = cmls_dec_vector_header(&header_ptr);
	assert(length_want == length_have);

	bytes header_have = {0};
	cmls_enc_vector_header(&header_have, length_want);
	assert(header_want.len == header_have.len);
	assert(memcmp(header_want.ptr, header_have.ptr, header_want.len) == 0);

	vec_free(&header_have);
	vec_free(&header_want);
}
