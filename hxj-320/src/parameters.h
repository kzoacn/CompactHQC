#ifndef HQC_PARAMETERS_H
#define HQC_PARAMETERS_H

/**
 * @file parameters.h
 * @brief Parameters of the HQC_KEM IND-CCA2 scheme
 */

#include "api.h"

#define CEIL_DIVIDE(a, b)  (((a)/(b)) + ((a) % (b) == 0 ? 0 : 1)) /*!< Divide a by b and ceil the result*/
#define BITMASK(a, size) ((1UL << (a % size)) - 1) /*!< Create a mask*/


/*
  #define PARAM_N                             	Define the parameter n of the scheme
  #define PARAM_N1                            	Define the parameter n1 of the scheme (length of Reed-Solomon code)
  #define PARAM_N2                            	Define the parameter n2 of the scheme (length of Duplicated Reed-Muller code)
  #define PARAM_N1N2                          	Define the length in bits of the Concatenated code
  #define PARAM_OMEGA                         	Define the parameter omega of the scheme
  #define PARAM_OMEGA_E                       	Define the parameter omega_e of the scheme
  #define PARAM_OMEGA_R                       	Define the parameter omega_r of the scheme
  #define PARAM_SECURITY                      	Define the security level corresponding to the chosen parameters
  #define PARAM_SECURITY_BYTES                  Define the the security level in bytes
  #define PARAM_DFR_EXP                       	Define the decryption failure rate corresponding to the chosen parameters

  #define SECRET_KEY_BYTES                    	Define the size of the secret key in bytes
  #define PUBLIC_KEY_BYTES                    	Define the size of the public key in bytes
  #define SHARED_SECRET_BYTES                 	Define the size of the shared secret in bytes
  #define CIPHERTEXT_BYTES                    	Define the size of the ciphertext in bytes

  #define UTILS_REJECTION_THRESHOLD           	Define the rejection threshold used to generate given weight vectors (see vector_set_random_fixed_weight function)
  #define VEC_N_SIZE_BYTES                    	Define the size of the array used to store a PARAM_N sized vector in bytes
  #define VEC_K_SIZE_BYTES                    	Define the size of the array used to store a PARAM_K sized vector in bytes
  #define VEC_N1Y_SIZE_BYTES                  	Define the size of the array used to store a PARAM_N1 sized vector in bytes
  #define VEC_N1N2_SIZE_BYTES                 	Define the size of the array used to store a PARAM_N1N2 sized vector in bytes

  #define VEC_N_SIZE_64                       	Define the size of the array used to store a PARAM_N sized vector in 64 bits
  #define VEC_K_SIZE_64                       	Define the size of the array used to store a PARAM_K sized vector in 64 bits
  #define VEC_N1_SIZE_64                      	Define the size of the array used to store a PARAM_N1 sized vector in 64 bits
  #define VEC_N1N2_SIZE_64                    	Define the size of the array used to store a PARAM_N1N2 sized vector in 64 bits

  #define PARAM_DELTA                         	Define the parameter delta of the scheme (correcting capacity of the Reed-Solomon code)
  #define PARAM_M                             	Define a positive integer
  #define PARAM_GF_POLY                       	Generator polynomial of galois field GF(2^PARAM_M), represented in hexadecimial form
  #define PARAM_GF_POLY_WT                      Hamming weight of PARAM_GF_POLY
  #define PARAM_GF_POLY_M2                      Distance between the primitive polynomial first two set bits
  #define PARAM_GF_MUL_ORDER                  	Define the size of the multiplicative group of GF(2^PARAM_M),  i.e 2^PARAM_M -1
  #define PARAM_K                             	Define the size of the information bits of the Reed-Solomon code
  #define PARAM_G                             	Define the size of the generator polynomial of Reed-Solomon code
  #define PARAM_FFT                           	The additive FFT takes a 2^PARAM_FFT polynomial as input
                                              	We use the FFT to compute the roots of sigma, whose degree if PARAM_DELTA=24
                                              	The smallest power of 2 greater than 24+1 is 32=2^5
  #define RS_POLY_COEFS                       	Coefficients of the generator polynomial of the Reed-Solomon code

  #define RED_MASK                            	A mask fot the higher bits of a vector
  #define SHAKE256_512_BYTES                    Define the size of SHAKE-256 output in bytes
  #define SEED_BYTES                          	Define the size of the seed in bytes
  #define SALT_SIZE_BYTES                       Define the size of a salt in bytes
  #define SALT_SIZE_64                          Define the size of a salt in 64 bits words
*/



#define PARAM_N																64037
#define PARAM_N1                            	100
#define PARAM_N2                            	640
#define PARAM_N1N2                          	(PARAM_N1*PARAM_N2)
#define PARAM_OMEGA                         	121
#define PARAM_OMEGA_E                       	121
#define PARAM_OMEGA_R                       	121
#define PARAM_SECURITY                      	320
#define PARAM_SECURITY_BYTES                  (PARAM_SECURITY/8)
#define PARAM_DFR_EXP                       	192


#define PARAM_DELTA                         	30
#define PARAM_M                            		8
#define PARAM_GF_POLY                       	0x11D
#define PARAM_GF_POLY_WT                      5
#define PARAM_GF_POLY_M2                        4
#define PARAM_GF_MUL_ORDER                  	255
#define PARAM_K                             	40
#define PARAM_G                             	(2*PARAM_DELTA+1)
#define PARAM_FFT                           	5


#define VEC_N_SIZE_BYTES                    	CEIL_DIVIDE(PARAM_N, 8)
#define VEC_K_SIZE_BYTES                    	PARAM_K
#define VEC_N1_SIZE_BYTES                   	PARAM_N1
#define VEC_N1N2_SIZE_BYTES                 	CEIL_DIVIDE(PARAM_N1N2, 8)

#define VEC_N_SIZE_64                       	CEIL_DIVIDE(PARAM_N, 64)
#define VEC_K_SIZE_64                       	CEIL_DIVIDE(PARAM_K, 8)
#define VEC_N1_SIZE_64                      	CEIL_DIVIDE(PARAM_N1, 8)
#define VEC_N1N2_SIZE_64                    	CEIL_DIVIDE(PARAM_N1N2, 64)

//#define RS_POLY_COEFS 49,167,49,39,200,121,124,91,240,63,148,71,150,123,87,101,32,215,159,71,201,115,97,210,186,183,141,217,123,12,31,243,180,219,152,239,99,141,4,246,191,144,8,232,47,27,141,178,130,64,124,47,39,188,216,48,199,187,1
//precompute by compute_generator_poly

#define RED_MASK                            	BITMASK(PARAM_N, 64)
#define SHAKE256_512_BYTES                    64
#define SEED_BYTES                          	64
#define SALT_SIZE_BYTES                       32
#define SALT_SIZE_64                          4

#define COMPRESSED_VEC_N_SIZE_64              CEIL_DIVIDE(VEC_N_SIZE_64*504, 512)
#define COMPRESSED_VEC_N1N2_SIZE_64           CEIL_DIVIDE(VEC_N1N2_SIZE_64*504, 512)
#define COMPRESSED_VEC_N_SIZE_BYTES           (COMPRESSED_VEC_N_SIZE_64*8)
#define COMPRESSED_VEC_N1N2_SIZE_BYTES        (COMPRESSED_VEC_N1N2_SIZE_64*8)


#define CRYPTO_PUBLICKEYBYTES               (SEED_BYTES + VEC_N_SIZE_BYTES)
#define CRYPTO_SECRETKEYBYTES               (SEED_BYTES + PARAM_SECURITY_BYTES + CRYPTO_PUBLICKEYBYTES)
#define CRYPTO_CIPHERTEXTBYTES              (COMPRESSED_VEC_N_SIZE_BYTES + COMPRESSED_VEC_N1N2_SIZE_BYTES + SALT_SIZE_BYTES)


#define SECRET_KEY_BYTES                    	CRYPTO_SECRETKEYBYTES
#define PUBLIC_KEY_BYTES                    	CRYPTO_PUBLICKEYBYTES
#define SHARED_SECRET_BYTES                 	CRYPTO_BYTES
#define CIPHERTEXT_BYTES                    	CRYPTO_CIPHERTEXTBYTES




// DEM parameters
#define DEM_KEY_SIZE 32  // 256-bit key
#define DEM_MSG_SIZE 32  
#define DEM_CT_SIZE  32  
#define DEM_IV_SIZE  12  
#define DEM_TAG_SIZE 12  

#endif