/**
 * @file ccapke.c
 * @brief Implementation of CCAPKE functions
 */

#include "api.h"
#include "hxj.h"
#include "parameters.h"
#include "parsing.h"
#include "shake_ds.h"
#include "vector.h"
#include <stdint.h>
#include <string.h>

// CCAPKE key generation
int crypto_ccapke_keypair(unsigned char *pk, unsigned char *sk) {
    // Generate KEM keypair
    int result = crypto_kem_keypair(pk, sk);
    if (result != 0) {
        return result;
    }
    return 0;
}

// CCAPKE encryption
int crypto_ccapke_enc(unsigned char *ct, unsigned char *ct_dem,
                     unsigned char *iv, unsigned char *tag,
                     const unsigned char *pk, const unsigned char *m) {
    uint8_t ss[SHARED_SECRET_BYTES] = {0};
    
    // Generate KEM ciphertext and shared secret
    int result = crypto_kem_enc(ct, ss, pk);

    //for(int i=0;i<SHARED_SECRET_BYTES;i++) printf("%d",ss[i]);
    //puts("");

    if (result != 0) {
        return result;
    }
    // Use DEM to encrypt message with shared secret
    int ret = crypto_dem_encaps(ss, m, ct_dem, iv, tag);

    return ret;
}

// CCAPKE decryption
int crypto_ccapke_dec(unsigned char *m,
                     const unsigned char *ct, const unsigned char *ct_dem,
                     const unsigned char *iv, const unsigned char *tag,
                     const unsigned char *sk) {
    uint8_t ss[SHARED_SECRET_BYTES] = {0};
    
    // Decapsulate KEM to get shared secret
    int result = crypto_kem_dec(ss, ct, sk);
    if (result != 0) {
        return result;
    }
    //for(int i=0;i<SHARED_SECRET_BYTES;i++) printf("%d",ss[i]);
    //puts("");

    // Use DEM to decrypt message with shared secret
    return crypto_dem_decaps(ss, ct_dem, iv, tag, m);
}
