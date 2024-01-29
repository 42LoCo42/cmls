#include "types.h"

void cmls_Capabilities_free(cmls_Capabilities* value) {
	vec_free(&value->versions);
	vec_free(&value->cipher_suites);
	vec_free(&value->extensions);
	vec_free(&value->proposals);
	vec_free(&value->credentials);
}

void cmls_LeafNode_free(cmls_LeafNode* value) {
	cmls_Capabilities_free(&value->capabilities);
	vec_free(&value->extensions);
}

void cmls_ParentNode_free(cmls_ParentNode* value) {
	vec_free(&value->unmerged_leaves);
}

void cmls_Node_free(cmls_Node* value) {
	switch(value->node_type) {
	case NodeType_Leaf:
		cmls_LeafNode_free(&value->data.leaf_node);
		break;
	case NodeType_Parent:
		cmls_ParentNode_free(&value->data.parent_node);
		break;
	default:
		break;
	}
}

void cmls_RatchetTree_free(cmls_RatchetTree* value) {
	for(size_t i = 0; i < value->len; i++) {
		cmls_Node_free(&value->ptr[i]);
	}
	vec_free(value);
}
