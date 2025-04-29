/**
 * @file code.cpp
 * @brief Implementation of concatenated code
 */

#include "code.h"
#include "reed_muller.h"
#include "reed_solomon.h"
#include "parameters.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#ifdef VERBOSE
#include <stdio.h>
#include "vector.h"
#endif


/**
 *
 * @brief Encoding the message m to a code word em using the concatenated code
 *
 * First we encode the message using the Reed-Solomon code, then with the duplicated Reed-Muller code we obtain
 * a concatenated code word.
 *
 * @param[out] em Pointer to an array that is the tensor code word
 * @param[in] m Pointer to an array that is the message
 */
void code_encode(uint64_t *em, const uint64_t *m) {
    uint64_t tmp[VEC_N1_SIZE_64] = {0};

    reed_solomon_encode(tmp, m);
    reed_muller_encode(em, tmp);

    #ifdef VERBOSE
        printf("\n\nReed-Solomon code word: "); vect_print(tmp, VEC_N1_SIZE_BYTES);
        printf("\n\nConcatenated code word: "); vect_print(em, VEC_N1N2_SIZE_BYTES);
    #endif
}

// Helper function to get a specific bit from uint64_t array
static uint8_t get_bit(const uint64_t *data, uint32_t pos) {
    uint32_t word = pos / 64;
    uint32_t bit = pos % 64;
    return (data[word] >> bit) & 0x1;
}

// Helper function to set a specific bit in uint64_t array
static void set_bit(uint64_t *data, uint32_t pos, uint8_t val) {
    uint32_t word = pos / 64;
    uint32_t bit = pos % 64;
    if (val) {
        data[word] |= (1ULL << bit);
    } else {
        data[word] &= ~(1ULL << bit);
    }
}

// Calculate parity bits for Hamming(511,502) code
static void calculate_parity_bits(uint64_t *codeword) {
    // Clear parity bits positions (powers of 2)
    for (uint32_t i = 1; i < 512; i <<= 1) {
        set_bit(codeword, i-1, 0);
    }

    // Calculate each parity bit
    for (uint32_t p = 1; p < 512; p <<= 1) {
        uint8_t parity = 0;
        for (uint32_t i = 1; i < 512; ++i) {
            if (i & p) {
                parity ^= get_bit(codeword, i-1);
            }
        }
        set_bit(codeword, p-1, parity);
    }
}

// Find and correct single bit error for Hamming(511,502)
static uint32_t locate_and_correct_error(uint64_t *codeword) {
    uint32_t syndrome = 0;
    for (uint32_t p = 1; p < 512; p <<= 1) {
        uint8_t parity = 0;
        for (uint32_t i = 1; i < 512; ++i) {
            if (i & p) {
                parity ^= get_bit(codeword, i-1);
            }
        }
        if (parity) {
            syndrome |= p;
        }
    }

    if (syndrome != 0) {
        set_bit(codeword, syndrome-1, get_bit(codeword, syndrome-1) ^ 1);
    }

    return syndrome;
}



/**
 * @brief Decoding the code word em to a message m using the concatenated code
 *
 * @param[out] m Pointer to an array that is the message
 * @param[in] em Pointer to an array that is the code word
 */
/**
 * @brief Encode 502-bit message to 511-bit Hamming code word
 *
 * @param[out] codeword Pointer to 8 uint64_t (512 bits, 511 used)
 * @param[in] message Pointer to 8 uint64_t (502 bits used)
 */
void hamming511_encode(uint64_t *codeword, const uint64_t *message) {
    // Copy message bits (skip parity positions)
    uint32_t msg_bit = 0;
    for (uint32_t i = 0; i < 511; ++i) {
        if ((i & (i+1)) != 0) { // Not a power of 2
            set_bit(codeword, i, get_bit(message, msg_bit++));
        }
    }

    calculate_parity_bits(codeword);

    #ifdef VERBOSE
        printf("\n\nHamming(511,502) encoded: ");
        vect_print(codeword, 64); // 512 bits = 64 bytes
    #endif
}

/**
 * @brief Decode 511-bit Hamming code to corrected code word
 *
 * @param[out] corrected_codeword Pointer to corrected 511-bit code word
 * @param[in] received Pointer to received 511-bit code word (may contain errors)
 */
void hamming511_decode_to_code(uint64_t *corrected_codeword, const uint64_t *received) {
    // Copy received data
    for (uint32_t i = 0; i < 8; ++i) {
        corrected_codeword[i] = received[i];
    }

    uint32_t error_pos = locate_and_correct_error(corrected_codeword);

    #ifdef VERBOSE
        printf("\n\nHamming(511,502) decode_to_code - error at position: %u", error_pos);
        printf("\nCorrected codeword: ");
        vect_print(corrected_codeword, 64);
    #endif
}

/**
 * @brief Decode 511-bit Hamming code to original 502-bit message
 *
 * @param[out] message Pointer to decoded 502-bit message
 * @param[in] received Pointer to received 511-bit code word (may contain errors)
 */
void hamming511_decode_to_message(uint64_t *message, const uint64_t *received) {
    uint64_t corrected[8] = {0};
    hamming511_decode_to_code(corrected, received);

    // Extract message bits (skip parity positions)
    uint32_t msg_bit = 0;
    for (uint32_t i = 0; i < 511; ++i) {
        if ((i & (i+1)) != 0) { // Not a power of 2
            set_bit(message, msg_bit++, get_bit(corrected, i));
        }
    }

    #ifdef VERBOSE
        printf("\n\nHamming(511,502) decode_to_message result: ");
        vect_print(message, 64); // 512 bits = 64 bytes (502 bits used)
    #endif
}

void code_decode(uint64_t *m, const uint64_t *em) {
    uint64_t tmp[VEC_N1_SIZE_64] = {0};

    reed_muller_decode(tmp, em);
    reed_solomon_decode(m, tmp);


    #ifdef VERBOSE
        printf("\n\nReed-Muller decoding result (the input for the Reed-Solomon decoding algorithm): "); vect_print(tmp, VEC_N1_SIZE_BYTES);
    #endif
}

/**
 * @brief Compress 512-bit input to 504-bit output using Hamming(511,502) code
 * 
 * Processes 512-bit input (8 uint64_t) to 504-bit output (8 uint64_t):
 * - First 511 bits are decoded using Hamming(511,502) to get 502-bit message
 * - The 512th input bit is processed based on error position
 * - Output contains 502-bit message + 1 processed bit + 1 fixed 0 bit
 *
 * @param[out] output Pointer to output buffer (8 uint64_t, 504 bits used)
 * @param[in] input Pointer to input data (8 uint64_t, 512 bits)
 * @note Output buffer will be zero-initialized before writing
 * @warning Input buffer must contain exactly 512 bits (8 uint64_t)
 */
void compress512(uint64_t *output, const uint64_t *input) {
    // Clear output
    for (int i = 0; i < 8; ++i) {
        output[i] = 0;
    }

    // Decode first 511 bits to get message and error position
    uint64_t message[8] = {0};
    uint64_t corrected[8] = {0};
    for (int i = 0; i < 8; ++i) {
        corrected[i] = input[i];
    }
    uint32_t error_pos = locate_and_correct_error(corrected);
    hamming511_decode_to_message(message, input);

    // Copy 502-bit message to output (positions 0-501)
    for (uint32_t i = 0; i < 502; ++i) {
        set_bit(output, i, get_bit(message, i));
    }

    // Process 512th input bit as flag (position 502 with 503 fixed to 0)
    uint8_t flag_bit = get_bit(input, 511);
    if (error_pos == 0) {
        flag_bit ^= 1; // Flip if no error
    }
    set_bit(output, 502, flag_bit);
    set_bit(output, 503, 0); // Fixed to 0 per specification

    #ifdef VERBOSE
        printf("\n\ncompress512 input: ");
        vect_print(input, 64);
        printf("\nError position: %u", error_pos);
        printf("\nOutput (504 bits): ");
        vect_print(output, 64);
    #endif
}

/**
 * @brief Decompress 504-bit input to 512-bit output (reverse of compress512)
 * 
 * Processes 504-bit input (8 uint64_t) to 512-bit output (8 uint64_t):
 * - First 502 bits are encoded to 511-bit Hamming code
 * - The 503rd input bit (flag bit) is restored to 512th output bit
 * - The 504th input bit is fixed to 0 per specification
 *
 * @param[out] output Pointer to output buffer (8 uint64_t, 512 bits)
 * @param[in] input Pointer to input data (8 uint64_t, 504 bits used)
 * @note Output buffer will be zero-initialized before writing
 * @warning Input buffer must contain exactly 504 bits (8 uint64_t)
 * @details The decompression process reverses the compression steps:
 *          1. Extract 502-bit message from input
 *          2. Encode to 511-bit Hamming code
 *          3. Restore 512th bit from flag bit (position 503)
 */
void decompress512(uint64_t *output, const uint64_t *input) {
    // Clear output
    for (int i = 0; i < 8; ++i) {
        output[i] = 0;
    }

    // Extract 502-bit message from input
    uint64_t message[8] = {0};
    for (uint32_t i = 0; i < 502; ++i) {
        set_bit(message, i, get_bit(input, i));
    }

    // Encode to 511-bit Hamming code
    hamming511_encode(output, message);

    // Get and process the flag bit (position 502) with 503 fixed to 0
    uint8_t flag_bit = get_bit(input, 502);
    // Reverse the flip done in compress512 when error_pos == 0
    set_bit(output, 511, flag_bit);

    #ifdef VERBOSE
        printf("\n\ndecompress512 input: ");
        vect_print(input, 64);
        printf("\nRestored 512th bit: %u", get_bit(output, 511));
        printf("\nOutput (512 bits): ");
        vect_print(output, 64);
    #endif
}




void compress(uint64_t *output, uint32_t size_out, const uint64_t *input, uint32_t size_in) {
    // Use temporary buffer to handle potential input/output overlap
    uint64_t *tmp_output = (uint64_t *)malloc(size_out * sizeof(uint64_t));
    if (!tmp_output) return;
    memset(tmp_output, 0, size_out * sizeof(uint64_t));

    uint32_t out_bit_pos = 0;
    uint32_t in_pos = 0;
    uint64_t chunk[8] = {0};

    while (in_pos < size_in) {
        uint32_t chunk_size = (size_in - in_pos) < 8 ? (size_in - in_pos) : 8;
        memcpy(chunk, input + in_pos, chunk_size * sizeof(uint64_t));
        if (chunk_size < 8) {
            memset(chunk + chunk_size, 0, (8 - chunk_size) * sizeof(uint64_t));
        }

        // Compress the chunk
        uint64_t compressed[8] = {0};
        compress512(compressed, chunk);

        for (uint32_t bit = 0; bit < 504; ++bit) {
            uint32_t out_word = out_bit_pos / 64;
            uint32_t out_bit = out_bit_pos % 64;
            if (out_word >= size_out) break; // Prevent buffer overflow

            uint8_t val = get_bit(compressed, bit);
            if (val) {
                tmp_output[out_word] |= (1ULL << out_bit);
            }
            out_bit_pos++;
        }

        in_pos += 8;
    }

    // Copy from temporary buffer to final output
    memcpy(output, tmp_output, size_out * sizeof(uint64_t));
    free(tmp_output);
}


void decompress(uint64_t *output, uint32_t size_out, const uint64_t *input, uint32_t size_in) {
    // Use temporary buffer to handle potential input/output overlap
    uint64_t *tmp_output = (uint64_t *)malloc(size_out * sizeof(uint64_t));
    if (!tmp_output) return;
    memset(tmp_output, 0, size_out * sizeof(uint64_t));

    uint32_t in_bit_pos = 0;
    uint32_t out_pos = 0;
    uint64_t chunk[8] = {0};

    while (in_bit_pos < size_in * 64 && out_pos < size_out) {

        for (uint32_t bit = 0; bit < 504; ++bit) {
            uint32_t in_word = in_bit_pos / 64;
            uint32_t in_bit = in_bit_pos % 64;
            if (in_word >= size_in) break; // Prevent buffer overflow

            uint8_t val = get_bit(input + in_word, in_bit);
            set_bit(chunk, bit, val);
            in_bit_pos++;
        }

        // Decompress the chunk
        uint64_t decompressed[8] = {0};
        decompress512(decompressed, chunk);

        uint32_t copy_size = (size_out - out_pos) < 8 ? (size_out - out_pos) : 8;
        memcpy(tmp_output + out_pos, decompressed, copy_size * sizeof(uint64_t));
        out_pos += 8;
    }

    // Copy from temporary buffer to final output
    memcpy(output, tmp_output, size_out * sizeof(uint64_t));
    free(tmp_output);
}
