/**
 * @file dem.c
 * @brief Implementation of DEM functions using AES-GCM
 */

#include "api.h"
#include "hxj.h"
#include "parameters.h"
#include "parsing.h"
#include "shake_ds.h"
#include "fips202.h"
#include "vector.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "aes-gcm.h"
#include "parameters.h"
#include "shake_prng.h"

// Generate 96-bit IV
static void gen_iv(unsigned char iv[DEM_IV_SIZE]) {
    shake_prng(iv,DEM_IV_SIZE);
}

int crypto_dem_encaps(const unsigned char *sk, const unsigned char *m,
                     unsigned char *ct, unsigned char *iv, unsigned char *tag) {
    // Generate IV
    gen_iv(iv);
    
    // Encrypt and generate tag using AES-GCM
    return aes256_gcm_enc(sk, iv, DEM_IV_SIZE, NULL, 0, 
                         m, DEM_MSG_SIZE, ct, tag, DEM_TAG_SIZE);
}

int crypto_dem_decaps(const unsigned char *sk, const unsigned char *ct,
                     const unsigned char *iv, const unsigned char *tag,
                     unsigned char *m) {
    // Decrypt and verify tag
    return aes256_gcm_dec(sk, iv, DEM_IV_SIZE, NULL, 0,
                         tag, DEM_TAG_SIZE, ct, DEM_CT_SIZE, m);
}
