// Dummy definitions of caffeine functions that we can link against

#include "caffeine.h"
#include <stdbool.h>
#include <stdlib.h>

void caffeine_assert(bool cond) {}
void caffeine_assume(bool cond) {}

void caffeine_make_symbolic(void* buf, size_t size, const char* name) {}
void* caffeine_builtin_symbolic_alloca(size_t size, const char* name) {
  return NULL;
}
