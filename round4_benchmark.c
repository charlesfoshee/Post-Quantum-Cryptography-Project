#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>
#include <time.h>

void cleanup(uint8_t *secret_key, uint8_t *shared_secret_e,
                  uint8_t *shared_secret_d, uint8_t *public_key,
                  uint8_t *ciphertext, OQS_KEM *kem) {
    if (kem != NULL) {
		OQS_MEM_secure_free(secret_key, kem->length_secret_key);
		OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
		OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(ciphertext);
	OQS_KEM_free(kem);
}

int main() {
    clock_t start, end;
    double cpu_time_used;
    OQS_KEM *kem = NULL;
    uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *ciphertext = NULL;
	uint8_t *shared_secret_e = NULL;
	uint8_t *shared_secret_d = NULL;

    OQS_init();
    OQS_STATUS rc;

    // Specify algorithm
    const char *kem_alg = OQS_KEM_alg_classic_mceliece_8192128f;
    kem = OQS_KEM_new(kem_alg);
    if (kem == NULL) {
        fprintf(stderr, "Failed to create KEM object for %s\n", kem_alg);
        OQS_destroy();
        return EXIT_FAILURE;
    }

    // Memory Allocation
    public_key = malloc(kem->length_public_key);
	secret_key = malloc(kem->length_secret_key);
	ciphertext = malloc(kem->length_ciphertext);
	shared_secret_e = malloc(kem->length_shared_secret);
	shared_secret_d = malloc(kem->length_shared_secret);
    if ((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) ||
	        (shared_secret_e == NULL) || (shared_secret_d == NULL)) {
		fprintf(stderr, "ERROR: malloc failed!\n");
		cleanup(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);
        OQS_destroy();
		return EXIT_FAILURE;
	}

    printf("Benchmarking %s...\n", kem_alg);

    // Key generation
    start = clock();
    rc = OQS_KEM_keypair(kem, public_key, secret_key);
    end = clock();
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_keypair failed!\n");
        cleanup(secret_key, shared_secret_e, shared_secret_d, public_key,
                        ciphertext, kem);
        OQS_destroy();
		return EXIT_FAILURE;
    }
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC * 1000;
    printf("Key generation time: %.3f ms\n", cpu_time_used);
    printf("Public key size: %zu bytes\n", kem->length_public_key);
    printf("Private key size: %zu bytes\n", kem->length_secret_key);

    // Encapsulation
    start = clock();
    rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
    end = clock();
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_encaps failed!\n");
        cleanup(secret_key, shared_secret_e, shared_secret_d, public_key,
                        ciphertext, kem);
        OQS_destroy();
		return EXIT_FAILURE;
    }
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC * 1000;
    printf("Encapsulation time: %.3f ms\n", cpu_time_used);
    printf("Ciphertext size: %zu bytes\n", kem->length_ciphertext);

    // Decapsulation
    start = clock();
    rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
    end = clock();
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_decaps failed!\n");
        cleanup(secret_key, shared_secret_e, shared_secret_d, public_key,
                        ciphertext, kem);
        OQS_destroy();
		return EXIT_FAILURE;
    }
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC * 1000;
    printf("Decapsulation time: %.3f ms\n", cpu_time_used);


    // Verify shared secrets match (indicative of successful encapsulation/decapsulation)
    if (OQS_MEM_secure_bcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret) == 0) {
        printf("Encapsulation/Decapsulation successful, shared secrets match.\n");
    } else {
        printf("Shared secrets do not match.\n");
    }
    cleanup(secret_key, shared_secret_e, shared_secret_d, public_key,
                        ciphertext, kem);    
    OQS_destroy();
    return EXIT_SUCCESS;
}
