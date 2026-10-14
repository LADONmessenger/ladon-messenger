#import "OQSWrapper.h"

#include <oqs/oqs.h>
#include <stddef.h>
#include <string.h>
#include <os/lock.h>

// FIX AUDIT-252: Thread-safety lock for liboqs operations
static os_unfair_lock oqs_lock = OS_UNFAIR_LOCK_INIT;

static OQS_KEM *OQS_new_kem(int32_t alg) {
    switch (alg) {
        case 1: // ML-KEM-768 (NIST FIPS 203, formerly Kyber768)
            return OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
        default:
            return NULL;
    }
}

static OQS_SIG *OQS_new_sig(int32_t alg) {
    switch (alg) {
        case 2: // Dilithium3
            return OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
        default:
            return NULL;
    }
}

// FIX AUDIT-246 + #248 + #249: Added buffer size validation, NULL checks, key zeroing on error
int32_t OQS_keypair_real(void *pk, uint64_t pkLen, void *sk, uint64_t skLen, int32_t alg) {
    // FIX AUDIT-248: NULL pointer checks
    if (pk == NULL || sk == NULL) return -2;
    
    os_unfair_lock_lock(&oqs_lock);
    OQS_KEM *kem = OQS_new_kem(alg);
    if (kem == NULL) {
        os_unfair_lock_unlock(&oqs_lock);
        return -1;
    }
    
    // FIX AUDIT-246: Validate buffer sizes (ML-KEM-768: pk=1184, sk=2400)
    if (pkLen < kem->length_public_key || skLen < kem->length_secret_key) {
        OQS_KEM_free(kem);
        os_unfair_lock_unlock(&oqs_lock);
        return -3;
    }
    
    OQS_STATUS status = OQS_KEM_keypair(kem, (uint8_t *)pk, (uint8_t *)sk);
    
    // FIX AUDIT-249: Zero secret key on failure
    if (status != OQS_SUCCESS) {
        memset_s(sk, skLen, 0, skLen);
    }
    
    OQS_KEM_free(kem);
    os_unfair_lock_unlock(&oqs_lock);
    return (int32_t)status;
}

int32_t OQS_encaps_real(void *ct, uint64_t ctLen, void *ss, uint64_t ssLen, const void *pk, uint64_t pkLen, int32_t alg) {
    if (ct == NULL || ss == NULL || pk == NULL) return -2;
    
    os_unfair_lock_lock(&oqs_lock);
    OQS_KEM *kem = OQS_new_kem(alg);
    if (kem == NULL) {
        os_unfair_lock_unlock(&oqs_lock);
        return -1;
    }
    
    if (ctLen < kem->length_ciphertext || ssLen < kem->length_shared_secret || pkLen < kem->length_public_key) {
        OQS_KEM_free(kem);
        os_unfair_lock_unlock(&oqs_lock);
        return -3;
    }
    
    OQS_STATUS status = OQS_KEM_encaps(kem, (uint8_t *)ct, (uint8_t *)ss, (const uint8_t *)pk);
    
    // FIX AUDIT-250: Zero shared secret on failure
    if (status != OQS_SUCCESS) {
        memset_s(ss, ssLen, 0, ssLen);
    }
    
    OQS_KEM_free(kem);
    os_unfair_lock_unlock(&oqs_lock);
    return (int32_t)status;
}

int32_t OQS_decaps_real(void *ss, uint64_t ssLen, const void *ct, uint64_t ctLen, const void *sk, uint64_t skLen, int32_t alg) {
    if (ss == NULL || ct == NULL || sk == NULL) return -2;
    
    os_unfair_lock_lock(&oqs_lock);
    OQS_KEM *kem = OQS_new_kem(alg);
    if (kem == NULL) {
        os_unfair_lock_unlock(&oqs_lock);
        return -1;
    }
    
    if (ssLen < kem->length_shared_secret || ctLen < kem->length_ciphertext || skLen < kem->length_secret_key) {
        OQS_KEM_free(kem);
        os_unfair_lock_unlock(&oqs_lock);
        return -3;
    }
    
    OQS_STATUS status = OQS_KEM_decaps(kem, (uint8_t *)ss, (const uint8_t *)ct, (const uint8_t *)sk);
    
    // FIX AUDIT-250: Zero shared secret on failure
    if (status != OQS_SUCCESS) {
        memset_s(ss, ssLen, 0, ssLen);
    }
    // NOTE MED-250: On success, caller is responsible for zeroing ss after use.
    // The shared secret must remain valid for the caller to consume it.
    // PostQuantumService.swift zeros via defer { sharedSecret.resetBytes(in: ...) }
    
    OQS_KEM_free(kem);
    os_unfair_lock_unlock(&oqs_lock);
    return (int32_t)status;
}

// FIX AUDIT-246 + #248 + #249: Signature operations with size validation
int32_t OQS_sig_keypair_real(void *pk, uint64_t pkLen, void *sk, uint64_t skLen, int32_t alg) {
    if (pk == NULL || sk == NULL) return -2;
    
    os_unfair_lock_lock(&oqs_lock);
    OQS_SIG *sig = OQS_new_sig(alg);
    if (sig == NULL) {
        os_unfair_lock_unlock(&oqs_lock);
        return -1;
    }
    
    // ML-DSA-65 (Dilithium3): pk=1952, sk=4032
    if (pkLen < sig->length_public_key || skLen < sig->length_secret_key) {
        OQS_SIG_free(sig);
        os_unfair_lock_unlock(&oqs_lock);
        return -3;
    }
    
    OQS_STATUS status = OQS_SIG_keypair(sig, (uint8_t *)pk, (uint8_t *)sk);
    
    if (status != OQS_SUCCESS) {
        memset_s(sk, skLen, 0, skLen);
    }
    
    OQS_SIG_free(sig);
    os_unfair_lock_unlock(&oqs_lock);
    return (int32_t)status;
}

// FIX AUDIT-251: Added sigBufLen parameter to prevent heap buffer overflow (sig=3309 bytes for Dilithium3)
int32_t OQS_sig_sign_real(void *sigBuf, uint64_t sigBufLen, uint64_t *sigLen, const void *msg, uint64_t msgLen, const void *sk, uint64_t skLen, int32_t alg) {
    if (sigBuf == NULL || msg == NULL || sk == NULL || sigLen == NULL) return -2;
    // FIX F-26: Reject zero-length messages — signing empty data is a logic error
    if (msgLen == 0) return -4;
    
    os_unfair_lock_lock(&oqs_lock);
    OQS_SIG *sig = OQS_new_sig(alg);
    if (sig == NULL) {
        os_unfair_lock_unlock(&oqs_lock);
        return -1;
    }
    
    // FIX AUDIT-251: Validate buffer can hold maximum signature size
    if (sigBufLen < sig->length_signature || skLen < sig->length_secret_key) {
        OQS_SIG_free(sig);
        os_unfair_lock_unlock(&oqs_lock);
        return -3;
    }
    
    size_t outLen = 0;
    OQS_STATUS status = OQS_SIG_sign(sig, (uint8_t *)sigBuf, &outLen, (const uint8_t *)msg, (size_t)msgLen, (const uint8_t *)sk);
    *sigLen = (uint64_t)outLen;
    
    OQS_SIG_free(sig);
    os_unfair_lock_unlock(&oqs_lock);
    return (int32_t)status;
}

int32_t OQS_sig_verify_real(const void *msg, uint64_t msgLen, const void *sigBuf, uint64_t sigLen, const void *pk, uint64_t pkLen, int32_t alg) {
    if (msg == NULL || sigBuf == NULL || pk == NULL) return -2;
    // FIX F-26: Reject zero-length messages — verifying empty data is a logic error
    if (msgLen == 0) return -4;
    
    os_unfair_lock_lock(&oqs_lock);
    OQS_SIG *sig = OQS_new_sig(alg);
    if (sig == NULL) {
        os_unfair_lock_unlock(&oqs_lock);
        return -1;
    }
    
    if (pkLen < sig->length_public_key) {
        OQS_SIG_free(sig);
        os_unfair_lock_unlock(&oqs_lock);
        return -3;
    }
    
    // FIX M-14: Validate signature length — reject oversized signatures before passing to liboqs
    if (sigLen > sig->length_signature) {
        OQS_SIG_free(sig);
        os_unfair_lock_unlock(&oqs_lock);
        return -3;
    }
    
    OQS_STATUS status = OQS_SIG_verify(sig, (const uint8_t *)msg, (size_t)msgLen, (const uint8_t *)sigBuf, (size_t)sigLen, (const uint8_t *)pk);
    OQS_SIG_free(sig);
    os_unfair_lock_unlock(&oqs_lock);
    return (int32_t)status;
}
