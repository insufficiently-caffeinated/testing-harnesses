
#include "caffeine.h"
#include <stdint.h>
#include <stdlib.h>

void* caffeine_builtin_symbolic_alloca(size_t size, const char* name);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);


// void __caffeine_entry_point(size_t size) {
//   uint8_t* buf = caffeine_builtin_symbolic_alloca(size, "__caffeine_mut");
//   LLVMFuzzerTestOneInput(buf, size);
// }

int main(int argc, char** argv) {
  size_t size = 128;
  uint8_t* buf = caffeine_builtin_symbolic_alloca(size, "__caffeine_mut");
  LLVMFuzzerTestOneInput(buf, size);
  return 0;
}
