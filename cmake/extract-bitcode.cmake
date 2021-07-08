
function(extract_bitcode TARGET FILE OUTPUT)
  set(intermediate_dir "${CMAKE_CURRENT_BINARY_DIR}/${TARGET}.dir")
  set(temp1 "${intermediate_dir}/extracted.bc")
  set(temp2 "${intermediate_dir}/linked.bc")

  make_directory("${intermediate_dir}")

  add_custom_command(
    OUTPUT "${OUTPUT}"
    COMMAND get-bc -o "${temp1}" "${FILE}"
    COMMAND llvm-link-11 -o "${temp2}" "${temp1}" "${CAFFEINE_BUILTINS}" "${CAFFEINE_LIBC}"
    COMMAND opt-11 --load "$<TARGET_FILE:caffeine::opt-plugin>" "${temp2}" 
      -o "${OUTPUT}" -S --caffeine-gen-builtins
    DEPENDS "${FILE}"
    BYPRODUCTS "${temp1}" "${temp2}"
  )

  add_custom_target(
    ${TARGET} ALL
    DEPENDS "${OUTPUT}"
  )
endfunction()
