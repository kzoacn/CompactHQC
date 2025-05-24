/**
 * @file ake.c 
 * @brief Implementation of Authenticated Key Exchange protocol
 */

#include "api.h"
#include "hxj.h"
#include "parameters.h"
#include "shake_ds.h"
#include "shake_prng.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// Hash function H1
static void H1(unsigned char *out, const unsigned char *r, const unsigned char *sk, size_t len) {
    shake256incctx state;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, r, 32);
    shake256_inc_absorb(&state, sk, len);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(out, 32, &state);
}

// Hash function H2 
static void H2(unsigned char *K, 
              const unsigned char *pk1, const unsigned char *pk2, const unsigned char *pk3,
              const unsigned char *c3, 
              const unsigned char *k1, const unsigned char *k2, const unsigned char *k3) {
    shake256incctx state;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, pk1, PUBLIC_KEY_BYTES);
    shake256_inc_absorb(&state, pk2, PUBLIC_KEY_BYTES);
    shake256_inc_absorb(&state, pk3, PUBLIC_KEY_BYTES);
    shake256_inc_absorb(&state, c3, CIPHERTEXT_BYTES);
    shake256_inc_absorb(&state, k1, SHARED_SECRET_BYTES);
    shake256_inc_absorb(&state, k2, SHARED_SECRET_BYTES);
    shake256_inc_absorb(&state, k3, DEM_MSG_SIZE);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(K, SHARED_SECRET_BYTES, &state);
}

// Alice's key generation
void alice_keygen(unsigned char *pk1, unsigned char *sk1) {
    crypto_kem_keypair(pk1, sk1);
}

// Bob's key generation  
void bob_keygen(unsigned char *pk2, unsigned char *sk2) {
    crypto_kem_keypair(pk2, sk2);
}

// Alice's key exchange
void alice_keyexchange(unsigned char *pk3, unsigned char *sk3,
                      unsigned char *c1, unsigned char *k1,
                      const unsigned char *pk2, const unsigned char *sk1) {
    // Generate PKE keypair
    crypto_ccapke_keypair(pk3, sk3);
    
    // Generate random r1
    unsigned char r1[32];
    shake_prng(r1,32);
    
    // Compute H1(r1, sk1)
    unsigned char h1[32];
    H1(h1, r1, sk1, SECRET_KEY_BYTES);
    
    // KEM Encaps
    crypto_kem_enc(c1, k1, pk2);
}

// Bob's key exchange
void bob_keyexchange(unsigned char *c2, unsigned char *k2,
                    unsigned char *c3, unsigned char *k3,
                    unsigned char *ct_dem, unsigned char *iv, unsigned char *tag,
                    const unsigned char *pk1, const unsigned char *sk2,
                    const unsigned char *pk3) {
    // Generate random r2
    unsigned char r2[32];
    //randombytes(r2, 32);
    shake_prng(r2,32);

    
    // Compute H1(r2, sk2)
    unsigned char h1[32];
    H1(h1, r2, sk2, SECRET_KEY_BYTES);
    
    // KEM Encaps
    crypto_kem_enc(c2, k2, pk1);
    
    // Generate random k3
    //randombytes(k3, 32);
    shake_prng(k3,DEM_MSG_SIZE);
    
    // PKE Encrypt
    crypto_ccapke_enc(c3, ct_dem, iv, tag, pk3, k3);
    
}

// Alice's final key computation
void alice_finalkey(unsigned char *K,
                   const unsigned char *pk1, const unsigned char *pk2, const unsigned char *pk3,
                   const unsigned char *c3, const unsigned char *ct_dem,
                   const unsigned char *iv, const unsigned char *tag,
                   const unsigned char *k1, const unsigned char *sk1,
                   const unsigned char *c2, const unsigned char *sk3) {
    unsigned char k2[SHARED_SECRET_BYTES];
    unsigned char k3[32];
    
    // KEM Decaps
    crypto_kem_dec(k2, c2, sk1);
    
    // PKE Decrypt
    crypto_ccapke_dec(k3, c3, ct_dem, iv, tag, sk3);
    
    // Compute final key
    /*printf("Alice computing final key with H2\n");
    printf("pk1: "); for(int i=0; i<10; i++) printf("%02x", pk1[i]); printf("\n");
    printf("pk2: "); for(int i=0; i<10; i++) printf("%02x", pk2[i]); printf("\n");
    printf("pk3: "); for(int i=0; i<10; i++) printf("%02x", pk3[i]); printf("\n");
    printf("c3: "); for(int i=0; i<10; i++) printf("%02x", c3[i]); printf("\n");
    printf("k1: "); for(int i=0; i<SHARED_SECRET_BYTES; i++) printf("%02x", k1[i]); printf("\n");
    printf("k2: "); for(int i=0; i<SHARED_SECRET_BYTES; i++) printf("%02x", k2[i]); printf("\n");
    printf("k3: "); for(int i=0; i<DEM_MSG_SIZE; i++) printf("%02x", k3[i]); printf("\n");*/
    H2(K, pk1, pk2, pk3, c3, k1, k2, k3);
    //printf("K: "); for(int i=0; i<10; i++) printf("%02x", K[i]); printf("\n");
}

// Bob's final key computation
void bob_finalkey(unsigned char *K,
                 const unsigned char *pk1, const unsigned char *pk2, const unsigned char *pk3,
                 const unsigned char *c3,
                 const unsigned char *k1, const unsigned char *k2, const unsigned char *k3) {
    // Compute final key
    /*printf("Bob computing final key with H2\n");
    printf("pk1: "); for(int i=0; i<10; i++) printf("%02x", pk1[i]); printf("\n");
    printf("pk2: "); for(int i=0; i<10; i++) printf("%02x", pk2[i]); printf("\n");
    printf("pk3: "); for(int i=0; i<10; i++) printf("%02x", pk3[i]); printf("\n");
    printf("c3: "); for(int i=0; i<10; i++) printf("%02x", c3[i]); printf("\n");
    printf("k1: "); for(int i=0; i<SHARED_SECRET_BYTES; i++) printf("%02x", k1[i]); printf("\n");
    printf("k2: "); for(int i=0; i<SHARED_SECRET_BYTES; i++) printf("%02x", k2[i]); printf("\n");
    printf("k3: "); for(int i=0; i<DEM_MSG_SIZE; i++) printf("%02x", k3[i]); printf("\n");*/
    H2(K, pk1, pk2, pk3, c3, k1, k2, k3);
    //printf("K: "); for(int i=0; i<10; i++) printf("%02x", K[i]); printf("\n");
}

// Main AKE protocol
void hxj_ake_protocol(unsigned char *K_alice, unsigned char *K_bob) {
    // Key generation
    unsigned char pk1[PUBLIC_KEY_BYTES], sk1[SECRET_KEY_BYTES];
    unsigned char pk2[PUBLIC_KEY_BYTES], sk2[SECRET_KEY_BYTES];
    alice_keygen(pk1, sk1);
    bob_keygen(pk2, sk2);
    
    // Key exchange
    unsigned char pk3[PUBLIC_KEY_BYTES], sk3[SECRET_KEY_BYTES];
    unsigned char c1[CIPHERTEXT_BYTES], k1[SHARED_SECRET_BYTES];
    unsigned char c2[CIPHERTEXT_BYTES], k2[SHARED_SECRET_BYTES];
    unsigned char c3[CIPHERTEXT_BYTES], k3[DEM_MSG_SIZE];
    unsigned char ct_dem[DEM_CT_SIZE], iv[DEM_IV_SIZE], tag[DEM_TAG_SIZE];
    
    alice_keyexchange(pk3, sk3, c1, k1, pk2, sk1);
    bob_keyexchange(c2, k2, c3, k3, ct_dem, iv, tag, pk1, sk2, pk3);
    
    // Final key computation
    alice_finalkey(K_alice, pk1, pk2, pk3, c3, ct_dem, iv, tag, k1, sk1, c2, sk3);
    bob_finalkey(K_bob, pk1, pk2, pk3, c3, k1, k2, k3);
    
    // Verify keys match
    if(memcmp(K_alice, K_bob, SHARED_SECRET_BYTES) != 0) {
        printf("AKE failed: keys don't match!\n");
    } else {
        printf("AKE succeeded!\n");
    }
}
