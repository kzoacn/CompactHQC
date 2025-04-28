/**
 * @file code.cpp
 * @brief Implementation of concatenated code
 */

#include "code.h"
#include "reed_muller.h"
#include "reed_solomon.h"
#include "parameters.h"
#include "vector.h"
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



/**
 * @brief Decoding the code word em to a message m using the concatenated code
 *
 * @param[out] m Pointer to an array that is the message
 * @param[in] em Pointer to an array that is the code word
 */
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

// Calculate parity bits for Hamming(255,247) code
static void calculate_parity_bits(uint64_t *codeword) {
    // Clear parity bits positions (powers of 2)
    for (uint32_t i = 1; i < 256; i <<= 1) {
        set_bit(codeword, i-1, 0);
    }

    // Calculate each parity bit
    for (uint32_t p = 1; p < 256; p <<= 1) {
        uint8_t parity = 0;
        for (uint32_t i = 1; i < 256; ++i) {
            if (i & p) {
                parity ^= get_bit(codeword, i-1);
            }
        }
        set_bit(codeword, p-1, parity);
    }
}

// Find and correct single bit error
static uint32_t locate_and_correct_error(uint64_t *codeword) {
    uint32_t syndrome = 0;
    for (uint32_t p = 1; p < 256; p <<= 1) {
        uint8_t parity = 0;
        for (uint32_t i = 1; i < 256; ++i) {
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
 * @brief Encode 247-bit message to 255-bit Hamming code word
 *
 * @param[out] codeword Pointer to 4 uint64_t (256 bits, 255 used)
 * @param[in] message Pointer to 4 uint64_t (247 bits used)
 */
void hamming255_encode(uint64_t *codeword, const uint64_t *message) {
    // Copy message bits (skip parity positions)
    uint32_t msg_bit = 0;
    for (uint32_t i = 0; i < 255; ++i) {
        if ((i & (i+1)) != 0) { // Not a power of 2
            set_bit(codeword, i, get_bit(message, msg_bit++));
        }
    }

    calculate_parity_bits(codeword);

    #ifdef VERBOSE
        printf("\n\nHamming(255,247) encoded: ");
        vect_print(codeword, 32); // 256 bits = 32 bytes
    #endif
}

/**
 * @brief Decode 255-bit Hamming code to corrected code word
 *
 * @param[out] corrected_codeword Pointer to corrected 255-bit code word
 * @param[in] received Pointer to received 255-bit code word (may contain errors)
 */
void hamming255_decode_to_code(uint64_t *corrected_codeword, const uint64_t *received) {
    // Copy received data
    for (uint32_t i = 0; i < 4; ++i) {
        corrected_codeword[i] = received[i];
    }

    uint32_t error_pos = locate_and_correct_error(corrected_codeword);

    #ifdef VERBOSE
        printf("\n\nHamming(255,247) decode_to_code - error at position: %u", error_pos);
        printf("\nCorrected codeword: ");
        vect_print(corrected_codeword, 32);
    #endif
}

/**
 * @brief Decode 255-bit Hamming code to original 247-bit message
 *
 * @param[out] message Pointer to decoded 247-bit message
 * @param[in] received Pointer to received 255-bit code word (may contain errors)
 */
void hamming255_decode_to_message(uint64_t *message, const uint64_t *received) {
    uint64_t corrected[4] = {0};
    hamming255_decode_to_code(corrected, received);

    // Extract message bits (skip parity positions)
    uint32_t msg_bit = 0;
    for (uint32_t i = 0; i < 255; ++i) {
        if ((i & (i+1)) != 0) { // Not a power of 2
            set_bit(message, msg_bit++, get_bit(corrected, i));
        }
    }

    #ifdef VERBOSE
        printf("\n\nHamming(255,247) decode_to_message result: ");
        vect_print(message, 32); // 256 bits = 32 bytes (247 bits used)
    #endif
}

/**
 * @brief Compress 256-bit input to 248-bit output (247-bit message + 1-bit flag)
 *
 * Processes 256-bit input (4 uint64_t) to 248-bit output (4 uint64_t):
 * - First 255 bits are decoded using Hamming(255,247) to get 247-bit message
 * - The 256th input bit is processed based on error position:
 *   - If error_pos != 0: keep original value
 *   - If error_pos == 0: flip the bit
 * - Output contains 247-bit message + 1 processed bit
 *
 * @param[out] output Pointer to 4 uint64_t (256 bits capacity, 248 bits used)
 * @param[in] input Pointer to 4 uint64_t (256 bits)
 */
void compress256(uint64_t *output, const uint64_t *input) {
    // Clear output
    for (int i = 0; i < 4; ++i) {
        output[i] = 0;
    }

    // Decode first 255 bits to get message and error position
    uint64_t message[4] = {0};
    uint64_t corrected[4] = {0};
    for (int i = 0; i < 4; ++i) {
        corrected[i] = input[i];
    }
    uint32_t error_pos = locate_and_correct_error(corrected);
    hamming255_decode_to_message(message, input);

    // Copy 247-bit message to output (positions 0-246)
    for (uint32_t i = 0; i < 247; ++i) {
        set_bit(output, i, get_bit(message, i));
    }

    // Process 256th input bit as flag (position 247 in output)
    uint8_t flag_bit = get_bit(input, 255);
    if (error_pos == 0) {
        flag_bit ^= 1; // Flip if no error
    }
    set_bit(output, 247, flag_bit);

    #ifdef VERBOSE
        printf("\n\ncompress256 input: ");
        vect_print(input, 32);
        printf("\nError position: %u", error_pos);
        printf("\nOutput (248 bits): ");
        vect_print(output, 32); // Still fits in 32 bytes
    #endif
}

/**
 * @brief Decompress 248-bit input to 256-bit output (reverse of compress256)
 *
 * Processes 248-bit input (4 uint64_t) to 256-bit output (4 uint64_t):
 * - First 247 bits are encoded to 255-bit Hamming code
 * - The 248th input bit is restored to 256th output bit
 *
 * @param[out] output Pointer to 4 uint64_t (256 bits)
 * @param[in] input Pointer to 4 uint64_t (248 bits used)
 */
void decompress256(uint64_t *output, const uint64_t *input) {
    // Clear output
    for (int i = 0; i < 4; ++i) {
        output[i] = 0;
    }

    // Extract 247-bit message from input
    uint64_t message[4] = {0};
    for (uint32_t i = 0; i < 247; ++i) {
        set_bit(message, i, get_bit(input, i));
    }

    // Encode to 255-bit Hamming code
    hamming255_encode(output, message);

    // Get and process the flag bit (position 247 in input)
    uint8_t flag_bit = get_bit(input, 247);
    set_bit(output, 255, flag_bit);

    #ifdef VERBOSE
        printf("\n\ndecompress256 input: ");
        vect_print(input, 32);
        printf("\nRestored 256th bit: %u", flag_bit);
        printf("\nOutput (256 bits): ");
        vect_print(output, 32);
    #endif
}

/**
 * @brief Compress input data by processing in 256-bit chunks (4 uint64_t)
 *
 * Processes input in chunks of 4 uint64_t (256 bits), applies compress256 to each,
 * and concatenates the 248-bit outputs. If input size isn't multiple of 4,
 * the final chunk is padded with zeros.
 *
 * @param[out] output Pointer to output buffer
 * @param[in] size_out Size of output buffer in uint64_t
 * @param[in] input Pointer to input data
 * @param[in] size_in Size of input data in uint64_t
 */
void compress(uint64_t *output, uint32_t size_out, const uint64_t *input, uint32_t size_in) {
    // Use temporary buffer to handle potential input/output overlap
    uint64_t *tmp_output = (uint64_t *)malloc(size_out * sizeof(uint64_t));
    if (!tmp_output) return;
    memset(tmp_output, 0, size_out * sizeof(uint64_t));

    uint32_t out_bit_pos = 0;
    uint32_t in_pos = 0;
    uint64_t chunk[4] = {0};

    while (in_pos < size_in) {
        // Prepare next 4-uint64_t chunk (pad with zeros if needed)
        uint32_t chunk_size = (size_in - in_pos) < 4 ? (size_in - in_pos) : 4;
        memcpy(chunk, input + in_pos, chunk_size * sizeof(uint64_t));
        if (chunk_size < 4) {
            memset(chunk + chunk_size, 0, (4 - chunk_size) * sizeof(uint64_t));
        }

        // Compress the chunk
        uint64_t compressed[4] = {0};
        compress256(compressed, chunk);

        // Copy compressed 248 bits to temporary output
        for (uint32_t bit = 0; bit < 248; ++bit) {
            uint32_t out_word = out_bit_pos / 64;
            uint32_t out_bit = out_bit_pos % 64;
            if (out_word >= size_out) break; // Prevent buffer overflow

            uint8_t val = get_bit(compressed, bit);
            if (val) {
                tmp_output[out_word] |= (1ULL << out_bit);
            }
            out_bit_pos++;
        }

        in_pos += 4;
    }

    // Copy from temporary buffer to final output
    memcpy(output, tmp_output, size_out * sizeof(uint64_t));
    free(tmp_output);
}

/**
 * @brief Decompress data by processing in 248-bit chunks (reverse of compress)
 *
 * Processes input in chunks of 248 bits, applies decompress256 to each,
 * and concatenates the 256-bit outputs.
 *
 * @param[out] output Pointer to output buffer
 * @param[in] size_out Size of output buffer in uint64_t
 * @param[in] input Pointer to input data
 * @param[in] size_in Size of input data in uint64_t
 */
void decompress(uint64_t *output, uint32_t size_out, const uint64_t *input, uint32_t size_in) {
    // Use temporary buffer to handle potential input/output overlap
    uint64_t *tmp_output = (uint64_t *)malloc(size_out * sizeof(uint64_t));
    if (!tmp_output) return;
    memset(tmp_output, 0, size_out * sizeof(uint64_t));

    uint32_t in_bit_pos = 0;
    uint32_t out_pos = 0;
    uint64_t chunk[4] = {0};

    while (in_bit_pos < size_in * 64 && out_pos < size_out) {
        // Prepare next 248-bit chunk from input
        for (uint32_t bit = 0; bit < 248; ++bit) {
            uint32_t in_word = in_bit_pos / 64;
            uint32_t in_bit = in_bit_pos % 64;
            if (in_word >= size_in) break; // Prevent buffer overflow

            uint8_t val = get_bit(input + in_word, in_bit);
            set_bit(chunk, bit, val);
            in_bit_pos++;
        }

        // Decompress the chunk
        uint64_t decompressed[4] = {0};
        decompress256(decompressed, chunk);

        // Copy decompressed 256 bits to temporary output
        uint32_t copy_size = (size_out - out_pos) < 4 ? (size_out - out_pos) : 4;
        memcpy(tmp_output + out_pos, decompressed, copy_size * sizeof(uint64_t));
        out_pos += 4;
    }

    // Copy from temporary buffer to final output
    memcpy(output, tmp_output, size_out * sizeof(uint64_t));
    free(tmp_output);
}

void code_decode(uint64_t *m, const uint64_t *em) {
    uint64_t tmp[VEC_N1_SIZE_64] = {0};

    reed_muller_decode(tmp, em);
    reed_solomon_decode(m, tmp);


    #ifdef VERBOSE
        printf("\n\nReed-Muller decoding result (the input for the Reed-Solomon decoding algorithm): "); vect_print(tmp, VEC_N1_SIZE_BYTES);
    #endif
}
