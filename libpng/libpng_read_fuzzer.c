
// libpng_read_fuzzer.cc
// Copyright 2017-2018 Glenn Randers-Pehrson
// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that may
// be found in the LICENSE file https://cs.chromium.org/chromium/src/LICENSE

// Last changed in libpng 1.6.35 [July 15, 2018]

// The modifications in 2017 by Glenn Randers-Pehrson include
// 1. addition of a PNG_CLEANUP macro,
// 2. setting the option to ignore ADLER32 checksums,
// 3. adding "#include <string.h>" which is needed on some platforms
//    to provide memcpy().
// 4. adding read_end_info() and creating an end_info structure.
// 5. adding calls to png_set_*() transforms commonly used by browsers.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "caffeine.h"

#define PNG_INTERNAL
#include "png.h"

#define nullptr NULL

#define PNG_CLEANUP                                                            \
  if (png_handler.png_ptr) {                                                   \
    if (png_handler.row_ptr)                                                   \
      png_free(png_handler.png_ptr, png_handler.row_ptr);                      \
    if (png_handler.end_info_ptr)                                              \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr,     \
                              &png_handler.end_info_ptr);                      \
    else if (png_handler.info_ptr)                                             \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr,     \
                              nullptr);                                        \
    else                                                                       \
      png_destroy_read_struct(&png_handler.png_ptr, nullptr, nullptr);         \
    png_handler.png_ptr = nullptr;                                             \
    png_handler.row_ptr = nullptr;                                             \
    png_handler.info_ptr = nullptr;                                            \
    png_handler.end_info_ptr = nullptr;                                        \
  }

typedef struct BufState {
  const uint8_t* data;
  size_t bytes_left;
} BufState;

typedef struct PngObjectHandler {
  png_infop info_ptr;
  png_structp png_ptr;
  png_infop end_info_ptr;
  png_voidp row_ptr;
  BufState* buf_state;
} PngObjectHandler;

void cleanup(PngObjectHandler* png_handler) {
  if (png_handler->png_ptr) {
    if (png_handler->row_ptr)
      png_free(png_handler->png_ptr, png_handler->row_ptr);
    if (png_handler->end_info_ptr)
      png_destroy_read_struct(&png_handler->png_ptr, &png_handler->info_ptr,
                              &png_handler->end_info_ptr);
    else if (png_handler->info_ptr)
      png_destroy_read_struct(&png_handler->png_ptr, &png_handler->info_ptr,
                              nullptr);
    else
      png_destroy_read_struct(&png_handler->png_ptr, nullptr, nullptr);
    png_handler->png_ptr = nullptr;
    png_handler->row_ptr = nullptr;
    png_handler->info_ptr = nullptr;
    png_handler->end_info_ptr = nullptr;
  }
}

void user_read_data(png_structp png_ptr, png_bytep data, size_t length) {
  BufState* buf_state = (BufState*)png_get_io_ptr(png_ptr);
  if (length > buf_state->bytes_left) {
    png_error(png_ptr, "read error");
  }
  memcpy(data, buf_state->data, length);
  buf_state->bytes_left -= length;
  buf_state->data += length;
}

void custom_error_fn(png_structp png, png_const_charp msg) {
  longjmp(png_jmpbuf(png), 1);
}
void custom_warning_fn(png_structp png, png_const_charp msg) {}

static const int kPngHeaderSize = 8;

// Entry point for LibFuzzer.
// Roughly follows the libpng book example:
// http://www.libpng.org/pub/png/book/chapter13.html
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < kPngHeaderSize) {
    return 0;
  }

  if (png_sig_cmp(data, 0, kPngHeaderSize)) {
    // not a PNG.
    return 0;
  }

  PngObjectHandler png_handler;
  memset(&png_handler, 0, sizeof(png_handler));

  png_handler.png_ptr =
      png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_handler.png_ptr) {
    return 0;
  }

  png_handler.info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.info_ptr) {
    goto cleanup;
  }

  png_handler.end_info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.end_info_ptr) {
    goto cleanup;
  }

  png_set_crc_action(png_handler.png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
#ifdef PNG_IGNORE_ADLER32
  png_set_option(png_handler.png_ptr, PNG_IGNORE_ADLER32, PNG_OPTION_ON);
#endif

  // Setting up reading from buffer.
  BufState buf_state;
  png_handler.buf_state = &buf_state;
  png_handler.buf_state->data = data + kPngHeaderSize;
  png_handler.buf_state->bytes_left = size - kPngHeaderSize;
  png_set_read_fn(png_handler.png_ptr, png_handler.buf_state, user_read_data);
  png_set_sig_bytes(png_handler.png_ptr, kPngHeaderSize);
  png_set_error_fn(png_handler.png_ptr, NULL, custom_error_fn, custom_warning_fn);

  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    goto cleanup;
  }

  // Reading.
  png_read_info(png_handler.png_ptr, png_handler.info_ptr);

  // reset error handler to put png_deleter into scope.
  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    goto cleanup;
  }

  png_uint_32 width, height;
  int bit_depth, color_type, interlace_type, compression_type;
  int filter_type;

  if (!png_get_IHDR(png_handler.png_ptr, png_handler.info_ptr, &width, &height,
                    &bit_depth, &color_type, &interlace_type, &compression_type,
                    &filter_type)) {
    goto cleanup;
  }

  // This is going to be too slow.
  if (width && height > 100000000 / width) {
    goto cleanup;
  }

  // Set several transforms that browsers typically use:
  png_set_gray_to_rgb(png_handler.png_ptr);
  png_set_expand(png_handler.png_ptr);
  png_set_packing(png_handler.png_ptr);
  png_set_scale_16(png_handler.png_ptr);
  png_set_tRNS_to_alpha(png_handler.png_ptr);

  int passes = png_set_interlace_handling(png_handler.png_ptr);

  png_read_update_info(png_handler.png_ptr, png_handler.info_ptr);

  png_handler.row_ptr =
      png_malloc(png_handler.png_ptr,
                 png_get_rowbytes(png_handler.png_ptr, png_handler.info_ptr));

  for (int pass = 0; pass < passes; ++pass) {
    for (png_uint_32 y = 0; y < height; ++y) {
      png_read_row(png_handler.png_ptr, (png_bytep)(png_handler.row_ptr),
                   nullptr);
    }
  }

  png_read_end(png_handler.png_ptr, png_handler.end_info_ptr);

cleanup:
  cleanup(&png_handler);
  return 0;
}
