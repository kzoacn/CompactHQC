/**
 * @file hqc.cpp
 * @brief Implementation of hqc.h
 */

 #include "hxj.h"
 #include "gf2x.h"
 #include "parameters.h"
 #include "parsing.h"
 #include "shake_prng.h"
 #include "code.h"
 #include "vector.h"
 #include <stdint.h>
 #ifdef VERBOSE
 #include <stdio.h>
 #endif
 
 
 /**
  * @brief Keygen of the HQC_PKE IND_CPA scheme
  *
  * The public key is composed of the syndrome <b>s</b> as well as the <b>seed</b> used to generate the vector <b>h</b>.
  *
  * The secret key is composed of the <b>seed</b> used to generate vectors <b>x</b> and  <b>y</b>.
  * As a technicality, the public key is appended to the secret key in order to respect NIST API.
  *
  * @param[out] pk String containing the public key
  * @param[out] sk String containing the secret key
  */
 void hxj_pke_keygen(unsigned char* pk, unsigned char* sk) {
     seedexpander_state sk_seedexpander;
     seedexpander_state pk_seedexpander;
     uint8_t sk_seed[SEED_BYTES] = {0};
     uint8_t sigma[PARAM_SECURITY_BYTES] = {0};
     uint8_t pk_seed[SEED_BYTES] = {0};
     uint64_t x[VEC_N_SIZE_64] = {0};
     uint64_t y[VEC_N_SIZE_64] = {0};
     uint64_t h[VEC_N_SIZE_64] = {0};
     uint64_t s[VEC_N_SIZE_64] = {0};
 
     // Create seed_expanders for public key and secret key
     shake_prng(sk_seed, SEED_BYTES);
     shake_prng(sigma, PARAM_SECURITY_BYTES);
     seedexpander_init(&sk_seedexpander, sk_seed, SEED_BYTES);
 
     shake_prng(pk_seed, SEED_BYTES);
     seedexpander_init(&pk_seedexpander, pk_seed, SEED_BYTES);
 
     // Compute secret key
     vect_set_random_fixed_weight(&sk_seedexpander, y, PARAM_OMEGA);
     vect_set_random_fixed_weight(&sk_seedexpander, x, PARAM_OMEGA);
 
     // Compute public key
     vect_set_random(&pk_seedexpander, h);
     vect_mul(s, y, h);
     vect_add(s, x, s, VEC_N_SIZE_64);
 
     // Parse keys to string
     hqc_public_key_to_string(pk, pk_seed, s);
     hqc_secret_key_to_string(sk, sk_seed, sigma, pk);
 
     #ifdef VERBOSE
         printf("\n\nsk_seed: "); for(int i = 0 ; i < SEED_BYTES ; ++i) printf("%02x", sk_seed[i]);
         printf("\n\nsigma: "); for(int i = 0 ; i < VEC_K_SIZE_BYTES ; ++i) printf("%02x", sigma[i]);
         printf("\n\nx: "); vect_print(x, VEC_N_SIZE_BYTES);
         printf("\n\ny: "); vect_print(y, VEC_N_SIZE_BYTES);
 
         printf("\n\npk_seed: "); for(int i = 0 ; i < SEED_BYTES ; ++i) printf("%02x", pk_seed[i]);
         printf("\n\nh: "); vect_print(h, VEC_N_SIZE_BYTES);
         printf("\n\ns: "); vect_print(s, VEC_N_SIZE_BYTES);
 
         printf("\n\nsk: "); for(int i = 0 ; i < SECRET_KEY_BYTES ; ++i) printf("%02x", sk[i]);
         printf("\n\npk: "); for(int i = 0 ; i < PUBLIC_KEY_BYTES ; ++i) printf("%02x", pk[i]);
     #endif
 }
 
 
 
 /**
  * @brief Encryption of the HQC_PKE IND_CPA scheme
  *
  * The cihertext is composed of vectors <b>u</b> and <b>v</b>.
  *
  * @param[out] u Vector u (first part of the ciphertext)
  * @param[out] v Vector v (second part of the ciphertext)
  * @param[in] m Vector representing the message to encrypt
  * @param[in] theta Seed used to derive randomness required for encryption
  * @param[in] pk String containing the public key
  */
 void hxj_pke_encrypt(uint64_t *compressed_u, uint64_t *compressed_v, uint64_t *m, unsigned char *theta, const unsigned char *pk) {
     seedexpander_state seedexpander;
 
     uint64_t u[VEC_N_SIZE_64] = {0};
     uint64_t v[VEC_N1N2_SIZE_64] = {0};
 
     uint64_t h[VEC_N_SIZE_64] = {0};
     uint64_t s[VEC_N_SIZE_64] = {0};
     //uint64_t r1[VEC_N_SIZE_64] = {0};
     uint64_t r2[VEC_N_SIZE_64] = {0};
     //uint64_t e[VEC_N_SIZE_64] = {0};
     uint64_t tmp1[VEC_N_SIZE_64] = {0};
     uint64_t tmp2[VEC_N_SIZE_64] = {0};
 
     // Create seed_expander from theta
     seedexpander_init(&seedexpander, theta, SEED_BYTES);
 
     // Retrieve h and s from public key
     hqc_public_key_from_string(h, s, pk);
 
     // Generate r1, r2 and e
     vect_set_random_fixed_weight(&seedexpander, r2, PARAM_OMEGA_R);
     //vect_set_random_fixed_weight(&seedexpander, e, PARAM_OMEGA_E);
     //vect_set_random_fixed_weight(&seedexpander, r1, PARAM_OMEGA_R);
 
     // Compute u = r1 + r2.h
     vect_mul(u, r2, h);
 
     compress(u,COMPRESSED_VEC_N_SIZE_64,u,VEC_N_SIZE_64);
     //vect_add(u, r1, u, VEC_N_SIZE_64);
     //for(int i=0;i+4<VEC_N_SIZE_64;i+=4)
     //    hamming255_decode_to_code(u+i,u+i);
     
 
     // Compute v = m.G by encoding the message
     code_encode(v, m);
     vect_resize(tmp1, PARAM_N, v, PARAM_N1N2);
 
     // Compute v = m.G + s.r2 + e
     vect_mul(tmp2, r2, s);
     //vect_add(tmp2, e, tmp2, VEC_N_SIZE_64);
 
     vect_add(tmp2, tmp1, tmp2, VEC_N_SIZE_64);
     vect_resize(v, PARAM_N1N2, tmp2, PARAM_N);
 
     compress(v,COMPRESSED_VEC_N1N2_SIZE_64,v,VEC_N1N2_SIZE_64);
 
     memcpy(compressed_u,u,COMPRESSED_VEC_N_SIZE_BYTES);
     memcpy(compressed_v,v,COMPRESSED_VEC_N1N2_SIZE_BYTES);
 
     #ifdef VERBOSE
         printf("\n\nh: "); vect_print(h, VEC_N_SIZE_BYTES);
         printf("\n\ns: "); vect_print(s, VEC_N_SIZE_BYTES);
         printf("\n\nr1: "); vect_print(r1, VEC_N_SIZE_BYTES);
         printf("\n\nr2: "); vect_print(r2, VEC_N_SIZE_BYTES);
         printf("\n\ne: "); vect_print(e, VEC_N_SIZE_BYTES);
         printf("\n\nnon-truncated v: "); vect_print(tmp2, VEC_N_SIZE_BYTES);
 
         printf("\n\nu: "); vect_print(u, VEC_N_SIZE_BYTES);
         printf("\n\nv: "); vect_print(v, VEC_N1N2_SIZE_BYTES);
     #endif
 }
 
 
 
 /**
  * @brief Decryption of the HQC_PKE IND_CPA scheme
  *
  * @param[out] m Vector representing the decrypted message
  * @param[in] u Vector u (first part of the ciphertext)
  * @param[in] v Vector v (second part of the ciphertext)
  * @param[in] sk String containing the secret key
  * @returns 0 
  */
 uint8_t hxj_pke_decrypt(uint64_t *m, uint8_t *sigma, const uint64_t *u, const uint64_t *v, const uint8_t *sk) {
     uint64_t y[VEC_N_SIZE_64] = {0};
     uint8_t pk[PUBLIC_KEY_BYTES] = {0};
     uint64_t tmp1[VEC_N_SIZE_64] = {0};
     uint64_t tmp2[VEC_N_SIZE_64] = {0};
 
     // Retrieve x, y, pk from secret key
     hqc_secret_key_from_string(y, sigma, pk, sk);
 
     uint64_t decompressed_u[VEC_N_SIZE_64] = {0};
     decompress(decompressed_u,VEC_N_SIZE_64,u,COMPRESSED_VEC_N_SIZE_64);
 
     uint64_t decompressed_v[VEC_N1N2_SIZE_64] = {0};
     decompress(decompressed_v,VEC_N1N2_SIZE_64,v,COMPRESSED_VEC_N1N2_SIZE_64);
 
     // Compute v - u.y
     vect_resize(tmp1, PARAM_N, decompressed_v, PARAM_N1N2);
     vect_mul(tmp2, y, decompressed_u);
     vect_add(tmp2, tmp1, tmp2, VEC_N_SIZE_64);
 
     #ifdef VERBOSE
         printf("\n\nu: "); vect_print(u, VEC_N_SIZE_BYTES);
         printf("\n\nv: "); vect_print(v, VEC_N1N2_SIZE_BYTES);
         printf("\n\ny: "); vect_print(y, VEC_N_SIZE_BYTES);
         printf("\n\nv - u.y: "); vect_print(tmp2, VEC_N_SIZE_BYTES);
     #endif
 
     // Compute m by decoding v - u.y
     code_decode(m, tmp2);
 
     return 0;
 }
 