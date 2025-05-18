#ifndef CODE_H
#define CODE_H

/**
 * @file code.h
 * @brief Header file of code.cpp
 */

#include "parameters.h"
#include <stddef.h>
#include <stdint.h>

void code_encode(uint64_t *codeword, const uint64_t *message);
void code_decode(uint64_t *message, const uint64_t *vector);

void hamming511_encode(uint64_t *codeword, const uint64_t *message);
void hamming511_decode_to_code(uint64_t *corrected_codeword, const uint64_t *received);
void hamming511_decode_to_message(uint64_t *message, const uint64_t *received);
void compress512(uint64_t *output, const uint64_t *input);
void decompress512(uint64_t *output, const uint64_t *input);
void compress(uint64_t *output, uint32_t size_out, const uint64_t *input, uint32_t size_in);
void decompress(uint64_t *output, uint32_t size_out, const uint64_t *input, uint32_t size_in);

#endif
