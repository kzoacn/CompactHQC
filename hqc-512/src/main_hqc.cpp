#include <stdio.h>
#include "api.h"
#include "parameters.h"
#include "gf.h"
#include "reed_solomon.h"

int main() {

	printf("\n");
	printf("*********************\n");
	printf("**** HQC-%d-%d ****\n", PARAM_SECURITY, PARAM_DFR_EXP);
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

	unsigned char pk[PUBLIC_KEY_BYTES];
	unsigned char sk[SECRET_KEY_BYTES];
	unsigned char ct[CIPHERTEXT_BYTES];
	unsigned char key1[SHARED_SECRET_BYTES];
	unsigned char key2[SHARED_SECRET_BYTES];

	crypto_kem_keypair(pk, sk);
	crypto_kem_enc(ct, key1, pk);
	crypto_kem_dec(key2, ct, sk);

	printf("\n\nsecret1: ");
	for(int i = 0 ; i < SHARED_SECRET_BYTES ; ++i) printf("%x", key1[i]);

	printf("\nsecret2: ");
	for(int i = 0 ; i < SHARED_SECRET_BYTES ; ++i) printf("%x", key2[i]);
	printf("\n\n");

	printf("pk size %d\n",SEED_BYTES + VEC_N_SIZE_BYTES);
	printf("sk size %d\n",SEED_BYTES + PARAM_SECURITY_BYTES + (SEED_BYTES + VEC_N_SIZE_BYTES));
	printf("ct size %d\n",VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES + SALT_SIZE_BYTES);
	

	for(int i = 0 ; i < SHARED_SECRET_BYTES ; ++i) 
	 if(key1[i]!=key2[i]){
		puts("NO!!!!!!!!!!!!!!");
		return 0;
	 }
	puts("YES");
 


	return 0;
}
