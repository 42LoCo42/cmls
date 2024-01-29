#ifndef CMLS_TREEMATH_H
#define CMLS_TREEMATH_H

#include <jansson.h>

int cmls_treemath_all_nodes(int partial_nodes);

int cmls_treemath_nodes(int leaves);
int cmls_treemath_root(int leaves);
int cmls_treemath_left(int node);
int cmls_treemath_right(int node);
int cmls_treemath_parent(int node, int leaves);
int cmls_treemath_sibling(int node, int leaves);

void cmls_treemath_test(const json_t* entry);

#endif
