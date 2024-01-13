#include "treemath.h"
#include "../utils/utils.h"
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

void cmls_treemath_test(char* line) {
	int  leaves  = atoi(strsep(&line, " "));
	int  nodes   = atoi(strsep(&line, " "));
	int  root    = atoi(strsep(&line, " "));
	ints left    = readints(strsep(&line, " "));
	ints right   = readints(strsep(&line, " "));
	ints parent  = readints(strsep(&line, " "));
	ints sibling = readints(strsep(&line, "\n"));

	assert(cmls_treemath_nodes(leaves) == nodes);
	assert(cmls_treemath_root(leaves) == root);

	for(int i = 0; i < leaves; i++) {
		assert(cmls_treemath_left(i) == vec_get(left, i));
		assert(cmls_treemath_right(i) == vec_get(right, i));
		assert(cmls_treemath_parent(i, leaves) == vec_get(parent, i));
		assert(cmls_treemath_sibling(i, leaves) == vec_get(sibling, i));
	}

	vec_free(left);
	vec_free(right);
	vec_free(parent);
	vec_free(sibling);
}
