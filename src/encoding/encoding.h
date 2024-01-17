#ifndef CMLS_ENCODING_H
#define CMLS_ENCODING_H

#include "../types/types.h"
#include "jansson.h"
#include <stdbool.h>

typedef enum {
	OPTIONAL_NO,
	OPTIONAL_OK,
	OPTIONAL_ERR,
} cmls_Optional;

uint8_t  cmls_dec_uint8(bytes* data);
uint16_t cmls_dec_uint16(bytes* data);
uint32_t cmls_dec_uint32(bytes* data);
uint64_t cmls_dec_uint64(bytes* data);

void          cmls_enc_optional(bytes* data, bool value);
cmls_Optional cmls_dec_optional(bytes* data);

void    cmls_enc_vector_header(bytes* data, size_t value);
ssize_t cmls_dec_vector_header(bytes* data);

void  cmls_enc_vector(bytes* data, bytes value);
bytes cmls_dec_vector(bytes* data);

#define declare_enum_dec(type) cmls_##type cmls_dec_##type(bytes* data)

declare_enum_dec(NodeType);
declare_enum_dec(ProtocolVersion);
declare_enum_dec(CipherSuiteType);
declare_enum_dec(ExtensionType);
declare_enum_dec(ProposalType);
declare_enum_dec(CredentialType);
declare_enum_dec(LeafNodeSource);

#undef declare_enum_dec

cmls_Credential cmls_dec_Credential(bytes* data);

cmls_Capabilities cmls_dec_Capabilities(bytes* data);

cmls_LifeTime cmls_dec_LifeTime(bytes* data);

cmls_Extension cmls_dec_Extension(bytes* data);

cmls_LeafNode cmls_dec_LeafNode(bytes* data);

cmls_ParentNode cmls_dec_ParentNode(bytes* data);

cmls_Node cmls_dec_Node(bytes* data);

void cmls_encoding_test(const json_t* entry);

#endif
