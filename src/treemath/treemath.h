#ifndef CMLS_TREEMATH_H
#define CMLS_TREEMATH_H

#include "../utils/utils.h"
#include "jansson.h"
#include <stdbool.h>

int cmls_treemath_nodes(int leaves);
int cmls_treemath_root(int leaves);
int cmls_treemath_left(int node);
int cmls_treemath_right(int node);
int cmls_treemath_parent(int node, int leaves);
int cmls_treemath_sibling(int node, int leaves);

void cmls_treemath_test(json_t* entry);

#endif
