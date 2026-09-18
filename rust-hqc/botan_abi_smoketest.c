/* Stands in for what Botan's HQC_KEM_Encryption/Decryption would do. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int hqc_sizes(uint8_t, size_t*, size_t*, size_t*, size_t*);
int hqc_keypair(uint8_t, uint8_t*, size_t, uint8_t*, size_t, const uint8_t*, size_t);
int hqc_encaps(uint8_t, uint8_t*, size_t, uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);
int hqc_decaps(uint8_t, uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);

int main(void) {
    uint8_t seed[48]; memset(seed, 9, sizeof seed);
    int bad = 0;
    for (int i = 0; i < 3; i++) {
        uint8_t ps = (uint8_t[]){1,3,5}[i];
        size_t ekl, dkl, ctl, ssl;
        if (hqc_sizes(ps, &ekl, &dkl, &ctl, &ssl)) { printf("sizes failed\n"); return 1; }
        uint8_t *ek = malloc(ekl), *dk = malloc(dkl), *ct = malloc(ctl);
        uint8_t *ss = malloc(ssl), *ss2 = malloc(ssl);
        int r1 = hqc_keypair(ps, ek, ekl, dk, dkl, seed, sizeof seed);
        int r2 = hqc_encaps(ps, ct, ctl, ss, ssl, ek, ekl, seed, sizeof seed);
        int r3 = hqc_decaps(ps, ss2, ssl, ct, ctl, dk, dkl);
        int match = (memcmp(ss, ss2, ssl) == 0);
        printf("  HQC-%u  ek=%zu dk=%zu ct=%zu ss=%zu  rc=%d/%d/%d  shared secret %s\n",
               ps, ekl, dkl, ctl, ssl, r1, r2, r3, match ? "MATCHES" : "DIFFERS");
        if (r1 || r2 || r3 || !match) bad = 1;
        free(ek); free(dk); free(ct); free(ss); free(ss2);
    }
    /* error paths must return codes, never abort */
    printf("  bad param set      -> %d\n", hqc_sizes(2, NULL, NULL, NULL, NULL));
    uint8_t s32[32];
    printf("  null ciphertext    -> %d\n", hqc_decaps(1, s32, 32, NULL, 0, NULL, 0));
    return bad;
}
