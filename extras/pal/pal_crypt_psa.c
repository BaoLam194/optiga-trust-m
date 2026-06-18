#include <string.h>
#include <stdio.h>
#include <psa/crypto.h>

#include "pal_crypt.h"
#include "pal_os_memory.h"

#define PAL_CRYPT_MAX_LABEL_SEED_LENGTH (96U)

static psa_status_t pal_psa_init_once(void)
{
    static int initialized = 0;
    
    if (!initialized) {
        psa_status_t st = psa_crypto_init();
        if (st != PSA_SUCCESS) {
            return st;
        }
        initialized = 1;
    }
    return PSA_SUCCESS;
}      

pal_status_t pal_crypt_tls_prf_sha256(pal_crypt_t *p_pal_crypt,
                                     const uint8_t *p_secret,
                                     uint16_t secret_length,
                                     const uint8_t *p_label,
                                     uint16_t label_length,
                                     const uint8_t *p_seed,
                                     uint16_t seed_length,
                                     uint8_t *p_derived_key,
                                     uint16_t derived_key_length)
{
    (void)p_pal_crypt;

    psa_status_t st;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;

    uint8_t label_seed[PAL_CRYPT_MAX_LABEL_SEED_LENGTH];
    size_t label_seed_len;

    uint8_t a[32];
    size_t a_len = 0;

#ifdef OPTIGA_LIB_DEBUG_NULL_CHECK
    if (p_secret == NULL || p_label == NULL || p_seed == NULL || p_derived_key == NULL)
        return PAL_STATUS_FAILURE;
#endif

    st = pal_psa_init_once();
    if (st != PSA_SUCCESS)
        return PAL_STATUS_FAILURE;

    if ((uint32_t)label_length + (uint32_t)seed_length > sizeof(label_seed))
        return PAL_STATUS_INVALID_INPUT;

    memcpy(label_seed, p_label, label_length);
    memcpy(label_seed + label_length, p_seed, seed_length);
    label_seed_len = (size_t)label_length + (size_t)seed_length;

    /* Import HMAC key */
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, (size_t)secret_length * 8u);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    st = psa_import_key(&attr, p_secret, (size_t)secret_length, &key_id);
    psa_reset_key_attributes(&attr);
    if (st != PSA_SUCCESS)
        return PAL_STATUS_FAILURE;

    /* A(1) */
    st = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                         label_seed, label_seed_len,
                         a, sizeof(a), &a_len);
    if (st != PSA_SUCCESS || a_len != 32) {
        psa_destroy_key(key_id);
        return PAL_STATUS_FAILURE;
    }

    size_t produced = 0;
    while (produced < (size_t)derived_key_length) {
        /* HMAC(secret, A(i) || label_seed) */
        psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
        uint8_t h[32];
        size_t h_len = 0;

        st = psa_mac_sign_setup(&op, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
        if (st != PSA_SUCCESS) break;

        st = psa_mac_update(&op, a, a_len);
        if (st != PSA_SUCCESS) { psa_mac_abort(&op); break; }

        st = psa_mac_update(&op, label_seed, label_seed_len);
        if (st != PSA_SUCCESS) { psa_mac_abort(&op); break; }

        st = psa_mac_sign_finish(&op, h, sizeof(h), &h_len);
        if (st != PSA_SUCCESS || h_len != 32) { psa_mac_abort(&op); break; }

        size_t to_copy = ((size_t)derived_key_length - produced < 32u) ?
                         ((size_t)derived_key_length - produced) : 32u;
        memcpy(p_derived_key + produced, h, to_copy);
        produced += to_copy;

        /* A(i+1) = HMAC(secret, A(i)) */
        st = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                             a, a_len,
                             a, sizeof(a), &a_len);
        if (st != PSA_SUCCESS || a_len != 32) break;
    }

    psa_destroy_key(key_id);

    return (st == PSA_SUCCESS && produced == (size_t)derived_key_length) ?
           PAL_STATUS_SUCCESS : PAL_STATUS_FAILURE;
}

pal_status_t pal_crypt_encrypt_aes128_ccm(pal_crypt_t *p_pal_crypt,
                                         const uint8_t *p_plain_text,
                                         uint16_t plain_text_length,
                                         const uint8_t *p_encrypt_key,
                                         const uint8_t *p_nonce,
                                         uint16_t nonce_length,
                                         const uint8_t *p_associated_data,
                                         uint16_t associated_data_length,
                                         uint8_t mac_size,
                                         uint8_t *p_cipher_text)
{
    (void)p_pal_crypt;

    psa_status_t st;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;

    size_t out_len = 0;

#ifdef OPTIGA_LIB_DEBUG_NULL_CHECK
    if (p_plain_text == NULL || p_encrypt_key == NULL || p_nonce == NULL ||
        p_associated_data == NULL || p_cipher_text == NULL)
        return PAL_STATUS_FAILURE;
#endif

    st = pal_psa_init_once();
    if (st != PSA_SUCCESS)
        return PAL_STATUS_FAILURE;

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, mac_size));

    st = psa_import_key(&attr, p_encrypt_key, 16, &key_id);
    psa_reset_key_attributes(&attr);
    if (st != PSA_SUCCESS)
        return PAL_STATUS_FAILURE;

    /* Output layout expected by existing code: ciphertext || tag */
    st = psa_aead_encrypt(key_id,
                          PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, mac_size),
                          p_nonce, nonce_length,
                          p_associated_data, associated_data_length,
                          p_plain_text, plain_text_length,
                          p_cipher_text, (size_t)plain_text_length + mac_size,
                          &out_len);

    psa_destroy_key(key_id);

    return (st == PSA_SUCCESS && out_len == (size_t)plain_text_length + mac_size) ?
           PAL_STATUS_SUCCESS : PAL_STATUS_FAILURE;
}

pal_status_t pal_crypt_decrypt_aes128_ccm(pal_crypt_t *p_pal_crypt,
                                         const uint8_t *p_cipher_text,
                                         uint16_t cipher_text_length,
                                         const uint8_t *p_decrypt_key,
                                         const uint8_t *p_nonce,
                                         uint16_t nonce_length,
                                         const uint8_t *p_associated_data,
                                         uint16_t associated_data_length,
                                         uint8_t mac_size,
                                         uint8_t *p_plain_text)
{
    (void)p_pal_crypt;

    psa_status_t st;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;

    size_t out_len = 0;

#ifdef OPTIGA_LIB_DEBUG_NULL_CHECK
    if (p_cipher_text == NULL || p_decrypt_key == NULL || p_nonce == NULL ||
        p_associated_data == NULL || p_plain_text == NULL)
        return PAL_STATUS_FAILURE;
#endif

    if (cipher_text_length < mac_size)
        return PAL_STATUS_INVALID_INPUT;

    st = pal_psa_init_once();
    if (st != PSA_SUCCESS)
        return PAL_STATUS_FAILURE;

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, mac_size));

    st = psa_import_key(&attr, p_decrypt_key, 16, &key_id);
    psa_reset_key_attributes(&attr);
    if (st != PSA_SUCCESS)
        return PAL_STATUS_FAILURE;

    st = psa_aead_decrypt(key_id,
                          PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, mac_size),
                          p_nonce, nonce_length,
                          p_associated_data, associated_data_length,
                          p_cipher_text, cipher_text_length,
                          p_plain_text, (size_t)cipher_text_length - mac_size,
                          &out_len);

    psa_destroy_key(key_id);

    return (st == PSA_SUCCESS && out_len == (size_t)cipher_text_length - mac_size) ?
           PAL_STATUS_SUCCESS : PAL_STATUS_FAILURE;
}

pal_status_t pal_crypt_version(uint8_t *p_crypt_lib_version_info, uint16_t *length)
{
    const char *v = "mbedTLS(PSA)";
    size_t vlen = strlen(v);

    if (p_crypt_lib_version_info == NULL || length == NULL)
        return PAL_STATUS_FAILURE;

    if (vlen > *length)
        return PAL_STATUS_FAILURE;

    pal_os_memcpy(p_crypt_lib_version_info, v, vlen);
    *length = (uint16_t)vlen;

    return PAL_STATUS_SUCCESS;
}
