/**
 * @file api.h
 * @brief NIST KEM API used by the HQC_KEM IND-CCA2 scheme
 */

#ifndef API_H
#define API_H

#include "parameters.h"

#define CRYPTO_ALGNAME                      "HXJ-320"

//#define CRYPTO_SECRETKEYBYTES               7317
//#define CRYPTO_PUBLICKEYBYTES               7245
#define CRYPTO_BYTES                        64
//#define CRYPTO_CIPHERTEXTBYTES              14421




// As a technicality, the public key is appended to the secret key in order to respect the NIST API.
// Without this constraint, CRYPTO_SECRETKEYBYTES would be defined as 32

int crypto_kem_keypair(unsigned char* pk, unsigned char* sk);
int crypto_kem_enc(unsigned char* ct, unsigned char* ss, const unsigned char* pk);
int crypto_kem_dec(unsigned char* ss, const unsigned char* ct, const unsigned char* sk);


int crypto_dem_encaps(const unsigned char *sk,const unsigned char *m,unsigned char *ct,unsigned char *iv,unsigned char *tag);
int crypto_dem_decaps(const unsigned char *sk,const unsigned char *ct,const unsigned char *iv,const unsigned char *tag, unsigned char *m);



int crypto_ccapke_keypair(unsigned char *pk, unsigned char *sk);
int crypto_ccapke_enc(unsigned char *ct, unsigned char *ct_dem,
                     unsigned char *iv, unsigned char *tag,
                     const unsigned char *pk, const unsigned char *m);

int crypto_ccapke_dec(unsigned char *m,
                     const unsigned char *ct, const unsigned char *ct_dem,
                     const unsigned char *iv, const unsigned char *tag,
                     const unsigned char *sk);

#endif
