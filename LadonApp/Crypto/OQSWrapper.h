#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// FIX AUDIT-246: Added buffer size parameters to prevent heap buffer overflows.
// ML-KEM-768: pk=1184, sk=2400, ct=1088, ss=32
// ML-DSA-65 (Dilithium3): pk=1952, sk=4032, sig=3309

// KEM operations with buffer size validation
int32_t OQS_keypair_real(void *pk, uint64_t pkLen, void *sk, uint64_t skLen, int32_t alg);
int32_t OQS_encaps_real(void *ct, uint64_t ctLen, void *ss, uint64_t ssLen, const void *pk, uint64_t pkLen, int32_t alg);
int32_t OQS_decaps_real(void *ss, uint64_t ssLen, const void *ct, uint64_t ctLen, const void *sk, uint64_t skLen, int32_t alg);

// Signature operations with buffer size validation
int32_t OQS_sig_keypair_real(void *pk, uint64_t pkLen, void *sk, uint64_t skLen, int32_t alg);
int32_t OQS_sig_sign_real(void *sig, uint64_t sigBufLen, uint64_t *sigLen, const void *msg, uint64_t msgLen, const void *sk, uint64_t skLen, int32_t alg);
int32_t OQS_sig_verify_real(const void *msg, uint64_t msgLen, const void *sig, uint64_t sigLen, const void *pk, uint64_t pkLen, int32_t alg);

#ifdef __cplusplus
}
#endif
