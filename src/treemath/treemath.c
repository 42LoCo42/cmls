#include "treemath.h"
#include "../utils/utils.h"
#include "jansson.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int log2x(int x) {
	if(x == 0) return 0;

	int k = 0;
	while(x >> k > 0) {
		k++;
	}

	return k - 1;
}

static int level(int x) {
	if((x & 0x01) == 0) return 0;

	int k = 0;
	while(((x >> k) & 0x01) == 1) {
		k++;
	}

	return k;
}

int cmls_treemath_nodes(int leaves) {
	return leaves == 0 ? 0 : 2 * (leaves - 1) + 1;
}

int cmls_treemath_root(int leaves) {
	int nodes = cmls_treemath_nodes(leaves);
	return (1 << log2x(nodes)) - 1;
}

int cmls_treemath_left(int node) {
	int k = level(node);
	return k == 0 ? -1 : node ^ (0x01 << (k - 1));
}

int cmls_treemath_right(int node) {
	int k = level(node);
	return k == 0 ? -1 : node ^ (0x03 << (k - 1));
}

int cmls_treemath_parent(int node, int leaves) {
	if(node == cmls_treemath_root(leaves)) return -1;

	int k = level(node);
	int b = (node >> (k + 1)) & 0x01;
	return (node | (1 << k)) ^ (b << (k + 1));
}

int cmls_treemath_sibling(int node, int leaves) {
	int p = cmls_treemath_parent(node, leaves);
	if(p == -1) return -1;
	if(node < p) {
		return cmls_treemath_right(p);
	} else {
		return cmls_treemath_left(p);
	}
}

void cmls_treemath_test(json_t* entry) {
	int     leaves  = json_integer_value(json_object_get(entry, "n_leaves"));
	int     nodes   = json_integer_value(json_object_get(entry, "n_nodes"));
	int     root    = json_integer_value(json_object_get(entry, "root"));
	json_t* left    = json_object_get(entry, "left");
	json_t* right   = json_object_get(entry, "right");
	json_t* parent  = json_object_get(entry, "parent");
	json_t* sibling = json_object_get(entry, "sibling");

	assert(cmls_treemath_nodes(leaves) == nodes);
	assert(cmls_treemath_root(leaves) == root);

	for(int i = 0; i < nodes; i++) {
		assert(cmls_treemath_left(i) == json_opt_int(json_array_get(left, i)));
		assert(
			cmls_treemath_right(i) == json_opt_int(json_array_get(right, i))
		);
		assert(
			cmls_treemath_parent(i, leaves) ==
			json_opt_int(json_array_get(parent, i))
		);
		assert(
			cmls_treemath_sibling(i, leaves) ==
			json_opt_int(json_array_get(sibling, i))
		);
	}
}
