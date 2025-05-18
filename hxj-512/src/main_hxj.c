#include <stdio.h>
#include <time.h>
#include "api.h"
#include "parameters.h"
#include "gf.h"
#include "reed_solomon.h"

int main() {

	printf("\n");
	printf("*********************\n");
	printf("**** HXJ-%d-%d ****\n", PARAM_SECURITY, PARAM_DFR_EXP);
	printf("*********************\n");

	printf("\n");
	printf("N: %d   ", PARAM_N);
	printf("N1: %d   ", PARAM_N1);
	printf("N2: %d   ", PARAM_N2);
	printf("OMEGA: %d   ", PARAM_OMEGA);
	printf("OMEGA_R: %d   ", PARAM_OMEGA_R);
	printf("Failure rate: 2^-%d   ", PARAM_DFR_EXP);
	printf("Sec: %d bits", PARAM_SECURITY);
	printf("\n");

	printf("OMEGA_E: %d   ", PARAM_OMEGA_E);
	printf("Security bytes: %d   ", PARAM_SECURITY_BYTES);
	printf("M: %d   ", PARAM_M);
	printf("GF_POLY: 0x%X   ", PARAM_GF_POLY);
	printf("K: %d   ", PARAM_K);
	printf("G: %d   ", PARAM_G);
	printf("FFT: %d   ", PARAM_FFT);
	printf("\n");
	printf("DELTA: %d   ", PARAM_DELTA);
	printf("GF_POLY_WT: %d   ", PARAM_GF_POLY_WT);
	printf("GF_POLY_M2: %d   ", PARAM_GF_POLY_M2);
	printf("GF_MUL_ORDER: %d   ", PARAM_GF_MUL_ORDER);
	printf("\n");
	printf("VEC_N_SIZE_BYTES: %d   ", VEC_N_SIZE_BYTES);
	printf("VEC_K_SIZE_BYTES: %d   ", VEC_K_SIZE_BYTES);
	printf("VEC_N1_SIZE_BYTES: %d   ", VEC_N1_SIZE_BYTES);
	printf("VEC_N1N2_SIZE_BYTES: %d   ", VEC_N1N2_SIZE_BYTES);
	printf("\n");
	printf("VEC_N_SIZE_64: %d   ", VEC_N_SIZE_64);
	printf("VEC_K_SIZE_64: %d   ", VEC_K_SIZE_64);
	printf("VEC_N1_SIZE_64: %d   ", VEC_N1_SIZE_64);
	printf("VEC_N1N2_SIZE_64: %d   ", VEC_N1N2_SIZE_64);
	printf("\n");
	printf("RED_MASK: 0x%lX   ", RED_MASK);
	printf("SHAKE256_512_BYTES: %d   ", SHAKE256_512_BYTES);
	printf("SEED_BYTES: %d   ", SEED_BYTES);
	printf("SALT_SIZE_BYTES: %d   ", SALT_SIZE_BYTES);
	printf("\n");
	printf("SALT_SIZE_64: %d   ", SALT_SIZE_64);
	printf("COMPRESSED_VEC_N_SIZE_64: %d   ", COMPRESSED_VEC_N_SIZE_64);
	printf("COMPRESSED_VEC_N1N2_SIZE_64: %d   ", COMPRESSED_VEC_N1N2_SIZE_64);
	printf("\n");
	printf("COMPRESSED_VEC_N_SIZE_BYTES: %d   ", COMPRESSED_VEC_N_SIZE_BYTES);
	printf("COMPRESSED_VEC_N1N2_SIZE_BYTES: %d   ", COMPRESSED_VEC_N1N2_SIZE_BYTES);
	printf("\n");

	printf("CRYPTO_PUBLICKEYBYTES: %d   ", CRYPTO_PUBLICKEYBYTES);
	printf("CRYPTO_SECRETKEYBYTES: %d   ", CRYPTO_SECRETKEYBYTES);
	printf("CRYPTO_CIPHERTEXTBYTES: %d   ", CRYPTO_CIPHERTEXTBYTES);
	printf("\n");

	unsigned char pk[PUBLIC_KEY_BYTES];
	unsigned char sk[SECRET_KEY_BYTES];
	unsigned char ct[CIPHERTEXT_BYTES];
	unsigned char key1[SHARED_SECRET_BYTES];
	unsigned char key2[SHARED_SECRET_BYTES];

	clock_t start, end;
	double keypair_time = 0, enc_time = 0, dec_time = 0;
	const int iterations = 100;
	
	// Single run first
	start = clock();
	crypto_kem_keypair(pk, sk);
	end = clock();
	keypair_time = ((double) (end - start)) / CLOCKS_PER_SEC * 1000;
	printf("\nSingle run keypair generation time: %.2f ms", keypair_time);
	
	start = clock();
	crypto_kem_enc(ct, key1, pk);
	end = clock();
	enc_time = ((double) (end - start)) / CLOCKS_PER_SEC * 1000;
	printf("\nSingle run encryption time: %.2f ms", enc_time);
	
	start = clock();
	crypto_kem_dec(key2, ct, sk);
	end = clock();
	dec_time = ((double) (end - start)) / CLOCKS_PER_SEC * 1000;
	printf("\nSingle run decryption time: %.2f ms\n", dec_time);
	
	// Run 100 times for average
	keypair_time = enc_time = dec_time = 0;
	for(int i = 0; i < iterations; i++) {
		start = clock();
		crypto_kem_keypair(pk, sk);
		end = clock();
		keypair_time += ((double) (end - start)) / CLOCKS_PER_SEC * 1000;
		
		start = clock();
		crypto_kem_enc(ct, key1, pk);
		end = clock();
		enc_time += ((double) (end - start)) / CLOCKS_PER_SEC * 1000;
		
		start = clock();
		crypto_kem_dec(key2, ct, sk);
		end = clock();
		dec_time += ((double) (end - start)) / CLOCKS_PER_SEC * 1000;
	}
	
	printf("\nAverage times after %d iterations:", iterations);
	printf("\nKeypair generation: %.2f ms", keypair_time/iterations);
	printf("\nEncryption: %.2f ms", enc_time/iterations);
	printf("\nDecryption: %.2f ms\n", dec_time/iterations);

	printf("\n\nsecret1: ");
	for(int i = 0 ; i < SHARED_SECRET_BYTES ; ++i) printf("%x", key1[i]);

	printf("\nsecret2: ");
	for(int i = 0 ; i < SHARED_SECRET_BYTES ; ++i) printf("%x", key2[i]);
	printf("\n\n");

	//printf("pk size %d\n",SEED_BYTES + VEC_N_SIZE_BYTES);
	//printf("sk size %d\n",SEED_BYTES + PARAM_SECURITY_BYTES + (SEED_BYTES + VEC_N_SIZE_BYTES));
	//printf("ct size %d\n",VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES + SALT_SIZE_BYTES);
	

	for(int i = 0 ; i < SHARED_SECRET_BYTES ; ++i) 
	 if(key1[i]!=key2[i]){
		puts("NO!!!!!!!!!!!!!!");
		return 0;
	 }
	puts("YES");

 

	


	return 0;
}
