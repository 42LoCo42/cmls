#ifndef CMLS_TYPES_H
#define CMLS_TYPES_H

#include "../utils/utils.h"

///// opaques /////

typedef bytes cmls_HPKEPublicKey;
typedef bytes cmls_SignaturePublicKey;

///// enums /////

typedef enum {
	NodeType_Reserved,
	NodeType_Leaf,
	NodeType_Parent,
	NodeType_FINAL,
} cmls_NodeType;

typedef enum {
	ProtocolVersion_Reserved,
	ProtocolVersion_MLS10,
	ProtocolVersion_FINAL,
} cmls_ProtocolVersion;

typedef enum {
	CipherSuiteType_MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
	CipherSuiteType_MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
	CipherSuiteType_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
	CipherSuiteType_MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
	CipherSuiteType_MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
	CipherSuiteType_MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
	CipherSuiteType_MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
	CipherSuiteType_FINAL,
} cmls_CipherSuiteType;

typedef enum {
	ExtensionType_Reserved,
	ExtensionType_ApplicationID,
	ExtensionType_RatchetTree,
	ExtensionType_RequiredCapabilities,
	ExtensionType_ExternalPub,
	ExtensionType_ExternalSenders,
	ExtensionType_FINAL,
} cmls_ExtensionType;

typedef enum {
	ProposalType_Add,
	ProposalType_Update,
	ProposalType_Remove,
	ProposalType_PSK,
	ProposalType_ReInit,
	ProposalType_ExternalInit,
	ProposalType_GroupContextExtensions,
	ProposalType_FINAL
} cmls_ProposalType;

typedef enum {
	CredentialType_Reserved,
	CredentialType_Basic,
	CredentialType_X509,
	CredentialType_FINAL,
} cmls_CredentialType;

typedef enum {
	LeafNodeSource_Reserved,
	LeafNodeSource_KeyPackage,
	LeafNodeSource_Update,
	LeafNodeSource_Commmit,
	LeafNodeSource_FINAL,
} cmls_LeafNodeSource;

///// structs /////

typedef struct {
	cmls_CredentialType credential_type;
	union {
		bytes identity;
		bytes cert_data;
	} data;
} cmls_Credential;

typedef struct {
	Vector(cmls_ProtocolVersion) versions;
	Vector(cmls_CipherSuiteType) cipher_suites;
	Vector(cmls_ExtensionType) extensions;
	Vector(cmls_ProposalType) proposals;
	Vector(cmls_CredentialType) credentials;
} cmls_Capabilities;

void cmls_Capabilities_free(cmls_Capabilities* value);

typedef struct {
	uint64_t not_before;
	uint64_t not_after;
} cmls_LifeTime;

typedef struct {
	cmls_ExtensionType extension_type;
	bytes              extension_data;
} cmls_Extension;

typedef struct {
	cmls_HPKEPublicKey      encryption_key;
	cmls_SignaturePublicKey signature_key;
	cmls_Credential         credential;
	cmls_Capabilities       capabilities;

	cmls_LeafNodeSource leaf_node_source;
	union {
		cmls_LifeTime lifetime;
		bytes         parent_hash;
	} data;

	Vector(cmls_Extension) extensions;
	bytes signature;
} cmls_LeafNode;

void cmls_LeafNode_free(cmls_LeafNode* value);

typedef struct {
	cmls_HPKEPublicKey encryption_key;
	bytes              parent_hash;
	Vector(uint32_t) unmerged_leaves;
} cmls_ParentNode;

void cmls_ParentNode_free(cmls_ParentNode* value);

typedef struct {
	cmls_NodeType node_type;
	union {
		cmls_LeafNode   leaf_node;
		cmls_ParentNode parent_node;
	} data;
} cmls_Node;

void cmls_Node_free(cmls_Node* value);

typedef Vector(cmls_Node) cmls_RatchetTree;

void cmls_RatchetTree_free(cmls_RatchetTree* value);

#endif
