
add_executable(libpng-read-fuzzer libpng_read_fuzzer.c)

target_link_libraries(libpng-read-fuzzer PRIVATE
  png_static caffeine-dummy caffeine-main
)

extract_bitcode(
  libpng-bitcode
  "$<TARGET_FILE:libpng-read-fuzzer>"
  libpng-bitcode.ll
)

add_dependencies(libpng-bitcode libpng-read-fuzzer)
