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
static void gen_iv(unsigned char *iv) {
    shake_prng(iv,DEM_IV_SIZE);
}

int crypto_dem_encaps(const unsigned char *sk, const unsigned char *m,
                     unsigned char *ct, unsigned char *iv, unsigned char *tag) {
    // Generate IV
    gen_iv(iv);
    
    /*printf("\nDEM Encaps Debug:");
    printf("\nKey: ");
    for(int i=0; i<8; i++) printf("%02X", sk[i]);
    printf("...");
    printf("\nMsg: ");
    for(int i=0; i<8; i++) printf("%02X", m[i]);
    printf("...");
    printf("\nIV: ");
    for(int i=0; i<DEM_IV_SIZE; i++) printf("%02X", iv[i]);*/

    // Encrypt and generate tag using AES-GCM
    int ret = aes256_gcm_enc(sk, NULL, 0, NULL, 0, m, DEM_MSG_SIZE, ct, tag, DEM_TAG_SIZE);

    /*printf("\nEnc Result: %s", ret == 0 ? "SUCCESS" : "FAIL");
    printf("\nCiphertext: ");
    for(int i=0; i<4; i++) printf("%02X", ct[i]);
    printf("...");
    printf("\nTag: ");
    for(int i=0; i<4; i++) printf("%02X", tag[i]);
    printf("...\n");
    printf("\nAfter IV: ");
    for(int i=0; i<DEM_IV_SIZE; i++) printf("%02X", iv[i]);*/


    return ret;
}

int crypto_dem_decaps(const unsigned char *sk, const unsigned char *ct,
                     const unsigned char *iv, const unsigned char *tag,
                     unsigned char *m) {

    /*printf("\nDEM Decaps Debug:");
    printf("\nKey: ");
    for(int i=0; i<8; i++) printf("%02X", sk[i]);
    printf("...");
    printf("\nCiphertext: ");
    for(int i=0; i<4; i++) printf("%02X", ct[i]);
    printf("...");
    printf("\nIV: ");
    for(int i=0; i<DEM_IV_SIZE; i++) printf("%02X", iv[i]);
    printf("\nTag: ");
    for(int i=0; i<4; i++) printf("%02X", tag[i]);
    printf("...");*/

    // Decrypt and verify tag
    int ret = aes256_gcm_dec(sk, NULL, 0, NULL, 0, tag, DEM_TAG_SIZE, ct, DEM_CT_SIZE, m);

    /*printf("\nDec Result: %s", ret == 0 ? "SUCCESS" : "FAIL");
    printf("\nMessage: ");
    for(int i=0; i<4; i++) printf("%02X", m[i]);
    printf("...\n");*/

    return ret;
}
