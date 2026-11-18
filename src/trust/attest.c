/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "attest.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

static int esys_initialize(ESYS_CONTEXT **ret, TSS2_TCTI_CONTEXT **ret_tcti) {
        ESYS_CONTEXT *context = NULL;
        TSS2_TCTI_CONTEXT *tcti = NULL;
        const char *tcti_conf;

        tcti_conf = getenv("TSS2_TCTI");
        if (!tcti_conf || !*tcti_conf) {
                if (access("/dev/tpmrm0", R_OK | W_OK) == 0)
                        tcti_conf = "device:/dev/tpmrm0";
                else if (access("/dev/tpm0", R_OK | W_OK) == 0)
                        tcti_conf = "device:/dev/tpm0";
                else
                        return -ENODEV;
        }

        if (Tss2_TctiLdr_Initialize(tcti_conf, &tcti) != TSS2_RC_SUCCESS) {
                Tss2_TctiLdr_Finalize(&tcti);
                return -EACCES;
        }
        if (Esys_Initialize(&context, tcti, NULL) != TSS2_RC_SUCCESS) {
                if (context)
                        Esys_Finalize(&context);
                Tss2_TctiLdr_Finalize(&tcti);
                return -EACCES;
        }
        if (Esys_SetTimeout(context, 2000) != TSS2_RC_SUCCESS) {
                Esys_Finalize(&context);
                Tss2_TctiLdr_Finalize(&tcti);
                return -EIO;
        }

        *ret = context;
        *ret_tcti = tcti;
        return 0;
}

static void esys_finalize(ESYS_CONTEXT **context, TSS2_TCTI_CONTEXT **tcti) {
        if (*context)
                Esys_Finalize(context);
        Tss2_TctiLdr_Finalize(tcti);
}

static int dup_bytes(const uint8_t *src, size_t n, uint8_t **out, size_t *out_len) {
        uint8_t *p = malloc(n ?: 1);
        if (!p)
                return -ENOMEM;
        memcpy(p, src, n);
        *out = p;
        *out_len = n;
        return 0;
}

/* A restricted ECC signing primary in the owner hierarchy: the AK. */
static const TPM2B_PUBLIC ak_template = {
        .publicArea = {
                .type = TPM2_ALG_ECC,
                .nameAlg = TPM2_ALG_SHA256,
                .objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT |
                                    TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                    TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH,
                .parameters.eccDetail = {
                        .symmetric = { .algorithm = TPM2_ALG_NULL },
                        .scheme = { .scheme = TPM2_ALG_ECDSA,
                                    .details.ecdsa.hashAlg = TPM2_ALG_SHA256 },
                        .curveID = TPM2_ECC_NIST_P256,
                        .kdf = { .scheme = TPM2_ALG_NULL },
                },
        },
};

/* The standard TCG ECC Endorsement Key (NIST P-256): a restricted decryption
 * primary in the endorsement hierarchy with the well-known EK auth policy
 * (PolicySecret over the endorsement auth). Used for credential activation. */
static const TPM2B_PUBLIC ek_template = {
        .publicArea = {
                .type = TPM2_ALG_ECC,
                .nameAlg = TPM2_ALG_SHA256,
                .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                    TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_ADMINWITHPOLICY |
                                    TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT,
                .authPolicy = {
                        .size = 32,
                        .buffer = {
                                0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8,
                                0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
                                0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
                                0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
                        },
                },
                .parameters.eccDetail = {
                        .symmetric = { .algorithm = TPM2_ALG_AES, .keyBits.aes = 128, .mode.aes = TPM2_ALG_CFB },
                        .scheme = { .scheme = TPM2_ALG_NULL },
                        .curveID = TPM2_ECC_NIST_P256,
                        .kdf = { .scheme = TPM2_ALG_NULL },
                },
                .unique.ecc = { .x = { .size = 32 }, .y = { .size = 32 } },
        },
};

/* Create a primary key from a template; returns its handle, public, and
 * (optionally) its TPM name. */
static int create_primary(ESYS_CONTEXT *ctx, ESYS_TR hierarchy, const TPM2B_PUBLIC *template,
                          ESYS_TR *handle, TPM2B_PUBLIC **pub, TPM2B_NAME **name) {
        static const TPM2B_SENSITIVE_CREATE in_sensitive = { 0 };
        static const TPM2B_DATA outside_info = { 0 };
        static const TPML_PCR_SELECTION creation_pcr = { 0 };

        if (Esys_CreatePrimary(ctx, hierarchy, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                               &in_sensitive, template, &outside_info, &creation_pcr,
                               handle, pub, NULL, NULL, NULL) != TSS2_RC_SUCCESS)
                return -EIO;
        if (name && Esys_TR_GetName(ctx, *handle, name) != TSS2_RC_SUCCESS)
                return -EIO;
        return 0;
}

int attest_quote(const uint8_t *nonce, size_t nonce_len,
                 uint8_t **ak_pub, size_t *ak_pub_len,
                 uint8_t **quoted, size_t *quoted_len,
                 uint8_t **sig, size_t *sig_len) {

        ESYS_CONTEXT *ctx = NULL;
        TSS2_TCTI_CONTEXT *tcti = NULL;
        ESYS_TR ak = ESYS_TR_NONE;
        TPM2B_PUBLIC *ak_public = NULL;
        TPM2B_ATTEST *attest = NULL;
        TPMT_SIGNATURE *signature = NULL;
        uint8_t pub_buf[sizeof(TPM2B_PUBLIC)], sig_buf[sizeof(TPMT_SIGNATURE)];
        size_t pub_off = 0, sig_off = 0;
        int r = -EIO;

        static const TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_NULL };   /* use the key's scheme */
        static const TPML_PCR_SELECTION pcr_select = {
                .count = 1,
                .pcrSelections[0] = {
                        .hash = TPM2_ALG_SHA256,
                        .sizeofSelect = 3,
                        .pcrSelect = { 0xFF, 0xFF, 0x00 },   /* PCRs 0..15 (boot); runtime log is in NV */
                },
        };
        TPM2B_DATA qualifying = { .size = (uint16_t) nonce_len };

        *ak_pub = *quoted = *sig = NULL;
        if (nonce_len == 0 || nonce_len > sizeof qualifying.buffer)
                return -EINVAL;
        memcpy(qualifying.buffer, nonce, nonce_len);

        if ((r = esys_initialize(&ctx, &tcti)) < 0)
                return r;
        r = -EIO;

        if (create_primary(ctx, ESYS_TR_RH_OWNER, &ak_template, &ak, &ak_public, NULL) < 0)
                goto out;

        if (Esys_Quote(ctx, ak, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                       &qualifying, &scheme, &pcr_select, &attest, &signature) != TSS2_RC_SUCCESS)
                goto out;

        if (Tss2_MU_TPM2B_PUBLIC_Marshal(ak_public, pub_buf, sizeof pub_buf, &pub_off) != TSS2_RC_SUCCESS ||
            Tss2_MU_TPMT_SIGNATURE_Marshal(signature, sig_buf, sizeof sig_buf, &sig_off) != TSS2_RC_SUCCESS)
                goto out;

        if (dup_bytes(pub_buf, pub_off, ak_pub, ak_pub_len) < 0 ||
            dup_bytes(attest->attestationData, attest->size, quoted, quoted_len) < 0 ||
            dup_bytes(sig_buf, sig_off, sig, sig_len) < 0) {
                r = -ENOMEM;
                goto out;
        }
        r = 0;
out:
        Esys_Free(ak_public);
        Esys_Free(attest);
        Esys_Free(signature);
        if (ak != ESYS_TR_NONE)
                Esys_FlushContext(ctx, ak);
        esys_finalize(&ctx, &tcti);
        if (r < 0) {
                free(*ak_pub);
                free(*quoted);
                free(*sig);
                *ak_pub = *quoted = *sig = NULL;
        }
        return r;
}

#define TRUSTD_NV_INDEX 0x01800001u

static int nv_open(ESYS_CONTEXT *ctx, ESYS_TR *nv, bool initialize) {
        static const TPM2B_AUTH empty = { .size = 0 };
        static const TPM2B_NV_PUBLIC expected = {
                .nvPublic = {
                        .nvIndex = TRUSTD_NV_INDEX,
                        .nameAlg = TPM2_ALG_SHA256,
                        .attributes = TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD |
                                      TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD |
                                      TPMA_NV_CLEAR_STCLEAR | TPMA_NV_NO_DA |
                                      (TPM2_NT_EXTEND << TPMA_NV_TPM2_NT_SHIFT),
                        .dataSize = 32,
                },
        };
        TPM2B_NV_PUBLIC *public = NULL;
        TSS2_RC rc;
        int r = -EIO;

        rc = Esys_TR_FromTPMPublic(ctx, TRUSTD_NV_INDEX, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, nv);
        if (rc != TSS2_RC_SUCCESS) {
                if ((rc & 0xffffU & ~TPM2_RC_N_MASK) != TPM2_RC_HANDLE)
                        return -EIO;
                if (!initialize)
                        return -ENOENT;
                if (Esys_NV_DefineSpace(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                       &empty, &expected, nv) != TSS2_RC_SUCCESS)
                        return -EIO;
        }
        if (Esys_NV_ReadPublic(ctx, *nv, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &public, NULL) != TSS2_RC_SUCCESS)
                return -EIO;
        if (public && public->nvPublic.nvIndex == TRUSTD_NV_INDEX &&
            public->nvPublic.nameAlg == expected.nvPublic.nameAlg &&
            public->nvPublic.dataSize == expected.nvPublic.dataSize &&
            public->nvPublic.authPolicy.size == 0 &&
            (public->nvPublic.attributes & ~TPMA_NV_WRITTEN) == expected.nvPublic.attributes)
                r = 0;
        else
                r = -EKEYREJECTED;
        Esys_Free(public);
        return r;
}

int attest_nv_initialize(void) {
        ESYS_CONTEXT *context = NULL;
        TSS2_TCTI_CONTEXT *tcti = NULL;
        ESYS_TR nv = ESYS_TR_NONE;
        int r;

        r = esys_initialize(&context, &tcti);
        if (r < 0)
                return r;
        r = nv_open(context, &nv, true);
        esys_finalize(&context, &tcti);
        return r;
}

int attest_nv_public(uint8_t **ret, size_t *ret_size) {
        ESYS_CONTEXT *context = NULL;
        TSS2_TCTI_CONTEXT *tcti = NULL;
        ESYS_TR nv = ESYS_TR_NONE;
        TPM2B_NV_PUBLIC *public = NULL;
        uint8_t buffer[sizeof(TPM2B_NV_PUBLIC)];
        size_t offset = 0;
        int r;

        *ret = NULL;
        *ret_size = 0;
        r = esys_initialize(&context, &tcti);
        if (r < 0)
                return r;
        r = nv_open(context, &nv, false);
        if (r < 0)
                goto finish;
        r = -EIO;
        if (Esys_NV_ReadPublic(context, nv, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &public, NULL) != TSS2_RC_SUCCESS ||
            Tss2_MU_TPM2B_NV_PUBLIC_Marshal(public, buffer, sizeof buffer, &offset) != TSS2_RC_SUCCESS)
                goto finish;
        r = dup_bytes(buffer, offset, ret, ret_size);
finish:
        Esys_Free(public);
        esys_finalize(&context, &tcti);
        return r;
}

int attest_nv_read(uint8_t value_out[32]) {
        ESYS_CONTEXT *ctx = NULL;
        TSS2_TCTI_CONTEXT *tcti = NULL;
        ESYS_TR nv = ESYS_TR_NONE;
        TPM2B_MAX_NV_BUFFER *data = NULL;
        TSS2_RC rc;
        int r = -EIO;

        memset(value_out, 0, 32);
        if ((r = esys_initialize(&ctx, &tcti)) < 0)
                return r;
        r = -EIO;
        if ((r = nv_open(ctx, &nv, false)) < 0)
                goto out;
        rc = Esys_NV_Read(ctx, ESYS_TR_RH_OWNER, nv, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          32, 0, &data);
        if (rc == TSS2_RC_SUCCESS && data && data->size == 32) {
                memcpy(value_out, data->buffer, 32);
                r = 0;
        } else if (rc == TPM2_RC_NV_UNINITIALIZED)
                r = 0;
        else
                r = -EIO;
out:
        Esys_Free(data);
        esys_finalize(&ctx, &tcti);
        return r;
}

int attest_nv_extend(const uint8_t *data, size_t len, uint8_t value_out[32]) {
        ESYS_CONTEXT *ctx = NULL;
        TSS2_TCTI_CONTEXT *tcti = NULL;
        ESYS_TR nv = ESYS_TR_NONE;
        TPM2B_MAX_NV_BUFFER in = { 0 }, *out = NULL;
        int r = -EIO;

        memset(value_out, 0, 32);
        if (len == 0 || len > sizeof in.buffer)
                return -EINVAL;
        in.size = (uint16_t) len;
        memcpy(in.buffer, data, len);
        if ((r = esys_initialize(&ctx, &tcti)) < 0)
                return r;
        r = -EIO;
        if ((r = nv_open(ctx, &nv, false)) < 0)
                goto out;
        r = -EIO;
        if (Esys_NV_Extend(ctx, ESYS_TR_RH_OWNER, nv, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &in) != TSS2_RC_SUCCESS)
                goto out;
        if (Esys_NV_Read(ctx, ESYS_TR_RH_OWNER, nv, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         32, 0, &out) != TSS2_RC_SUCCESS || !out || out->size != 32)
                goto out;
        memcpy(value_out, out->buffer, 32);
        r = 0;
out:
        Esys_Free(out);
        esys_finalize(&ctx, &tcti);
        return r;
}

int attest_nv_certify(const uint8_t *nonce, size_t nonce_len,
                      uint8_t **ak_pub, size_t *ak_pub_len,
                      uint8_t **certify_info, size_t *certify_info_len,
                      uint8_t **sig, size_t *sig_len) {
        static const TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_NULL };
        ESYS_CONTEXT *ctx = NULL;
        TSS2_TCTI_CONTEXT *tcti = NULL;
        ESYS_TR ak = ESYS_TR_NONE, nv = ESYS_TR_NONE;
        TPM2B_PUBLIC *ak_public = NULL;
        TPM2B_ATTEST *attest = NULL;
        TPMT_SIGNATURE *signature = NULL;
        uint8_t pub_buf[sizeof(TPM2B_PUBLIC)], sig_buf[sizeof(TPMT_SIGNATURE)];
        size_t pub_off = 0, sig_off = 0;
        TPM2B_DATA qualifying = { .size = (uint16_t) nonce_len };
        int r = -EIO;

        *ak_pub = *certify_info = *sig = NULL;
        if (nonce_len == 0 || nonce_len > sizeof qualifying.buffer)
                return -EINVAL;
        memcpy(qualifying.buffer, nonce, nonce_len);
        if ((r = esys_initialize(&ctx, &tcti)) < 0)
                return r;
        r = -EIO;
        if ((r = nv_open(ctx, &nv, false)) < 0)
                goto out;
        r = -EIO;
        if (create_primary(ctx, ESYS_TR_RH_OWNER, &ak_template, &ak, &ak_public, NULL) < 0)
                goto out;
        if (Esys_NV_Certify(ctx, ak, ESYS_TR_RH_OWNER, nv,
                            ESYS_TR_PASSWORD, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                            &qualifying, &scheme, 32, 0, &attest, &signature) != TSS2_RC_SUCCESS)
                goto out;
        if (Tss2_MU_TPM2B_PUBLIC_Marshal(ak_public, pub_buf, sizeof pub_buf, &pub_off) != TSS2_RC_SUCCESS ||
            Tss2_MU_TPMT_SIGNATURE_Marshal(signature, sig_buf, sizeof sig_buf, &sig_off) != TSS2_RC_SUCCESS)
                goto out;
        if (dup_bytes(pub_buf, pub_off, ak_pub, ak_pub_len) < 0 ||
            dup_bytes(attest->attestationData, attest->size, certify_info, certify_info_len) < 0 ||
            dup_bytes(sig_buf, sig_off, sig, sig_len) < 0) {
                r = -ENOMEM;
                goto out;
        }
        r = 0;
out:
        Esys_Free(ak_public);
        Esys_Free(attest);
        Esys_Free(signature);
        if (ak != ESYS_TR_NONE)
                Esys_FlushContext(ctx, ak);
        esys_finalize(&ctx, &tcti);
        if (r < 0) {
                free(*ak_pub);
                free(*certify_info);
                free(*sig);
                *ak_pub = *certify_info = *sig = NULL;
        }
        return r;
}

static int read_ek_certificate(ESYS_CONTEXT *ctx, uint8_t **ret, size_t *ret_size) {
        ESYS_TR nv = ESYS_TR_NONE;
        TPM2B_NV_PUBLIC *public = NULL;
        TPMS_CAPABILITY_DATA *capabilities = NULL;
        TPMI_YES_NO more;
        uint8_t *buffer = NULL;
        size_t limit, size;
        TSS2_RC rc;
        int r = -EIO;

        rc = Esys_TR_FromTPMPublic(ctx, 0x01C0000A, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nv);
        if (rc != TSS2_RC_SUCCESS)
                return (rc & 0xffffU & ~TPM2_RC_N_MASK) == TPM2_RC_HANDLE ? 0 : -EIO;
        if (Esys_NV_ReadPublic(ctx, nv, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &public, NULL) != TSS2_RC_SUCCESS ||
            Esys_GetCapability(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               TPM2_CAP_TPM_PROPERTIES, TPM2_PT_NV_BUFFER_MAX, 1, &more, &capabilities) != TSS2_RC_SUCCESS ||
            !public || !capabilities || capabilities->capability != TPM2_CAP_TPM_PROPERTIES ||
            capabilities->data.tpmProperties.count != 1 ||
            capabilities->data.tpmProperties.tpmProperty[0].property != TPM2_PT_NV_BUFFER_MAX)
                goto finish;
        limit = capabilities->data.tpmProperties.tpmProperty[0].value;
        if (limit > sizeof(((TPM2B_MAX_NV_BUFFER *) 0)->buffer))
                limit = sizeof(((TPM2B_MAX_NV_BUFFER *) 0)->buffer);
        size = public->nvPublic.dataSize;
        if (limit == 0 || size == 0)
                goto finish;
        buffer = malloc(size);
        if (!buffer) {
                r = -ENOMEM;
                goto finish;
        }
        for (size_t offset = 0; offset < size;) {
                TPM2B_MAX_NV_BUFFER *data = NULL;
                size_t chunk = size - offset < limit ? size - offset : limit;
                ESYS_TR auth = public->nvPublic.attributes & TPMA_NV_OWNERREAD ? ESYS_TR_RH_OWNER : nv;

                rc = Esys_NV_Read(ctx, auth, nv, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                  (UINT16) chunk, (UINT16) offset, &data);
                if (rc != TSS2_RC_SUCCESS || !data || data->size != chunk) {
                        Esys_Free(data);
                        goto finish;
                }
                memcpy(buffer + offset, data->buffer, chunk);
                offset += chunk;
                Esys_Free(data);
        }
        *ret = buffer;
        *ret_size = size;
        buffer = NULL;
        r = 0;
finish:
        free(buffer);
        Esys_Free(public);
        Esys_Free(capabilities);
        if (nv != ESYS_TR_NONE)
                Esys_TR_Close(ctx, &nv);
        return r;
}

int attest_get_enrollment(uint8_t **ek_pub, size_t *ek_pub_len,
                          uint8_t **ek_cert, size_t *ek_cert_len,
                          uint8_t **ak_pub, size_t *ak_pub_len,
                          uint8_t **ak_name, size_t *ak_name_len) {
        ESYS_CONTEXT *ctx = NULL;
        TSS2_TCTI_CONTEXT *tcti = NULL;
        ESYS_TR ek = ESYS_TR_NONE, ak = ESYS_TR_NONE;
        TPM2B_PUBLIC *ekp = NULL, *akp = NULL;
        TPM2B_NAME *akn = NULL;
        uint8_t ek_buf[sizeof(TPM2B_PUBLIC)], ak_buf[sizeof(TPM2B_PUBLIC)];
        size_t ek_off = 0, ak_off = 0;
        int r = -EIO;

        *ek_pub = *ek_cert = *ak_pub = *ak_name = NULL;
        *ek_pub_len = *ek_cert_len = *ak_pub_len = *ak_name_len = 0;

        if ((r = esys_initialize(&ctx, &tcti)) < 0)
                return r;
        r = -EIO;
        if (create_primary(ctx, ESYS_TR_RH_ENDORSEMENT, &ek_template, &ek, &ekp, NULL) < 0 ||
            create_primary(ctx, ESYS_TR_RH_OWNER, &ak_template, &ak, &akp, &akn) < 0)
                goto out;
        if (Tss2_MU_TPM2B_PUBLIC_Marshal(ekp, ek_buf, sizeof ek_buf, &ek_off) != TSS2_RC_SUCCESS ||
            Tss2_MU_TPM2B_PUBLIC_Marshal(akp, ak_buf, sizeof ak_buf, &ak_off) != TSS2_RC_SUCCESS)
                goto out;
        if (dup_bytes(ek_buf, ek_off, ek_pub, ek_pub_len) < 0 ||
            dup_bytes(ak_buf, ak_off, ak_pub, ak_pub_len) < 0 ||
            dup_bytes(akn->name, akn->size, ak_name, ak_name_len) < 0) {
                r = -ENOMEM;
                goto out;
        }

        r = read_ek_certificate(ctx, ek_cert, ek_cert_len);
out:
        Esys_Free(ekp);
        Esys_Free(akp);
        Esys_Free(akn);
        if (ek != ESYS_TR_NONE)
                Esys_FlushContext(ctx, ek);
        if (ak != ESYS_TR_NONE)
                Esys_FlushContext(ctx, ak);
        esys_finalize(&ctx, &tcti);
        if (r < 0) {
                free(*ek_pub);
                free(*ek_cert);
                free(*ak_pub);
                free(*ak_name);
                *ek_pub = *ek_cert = *ak_pub = *ak_name = NULL;
                *ek_pub_len = *ek_cert_len = *ak_pub_len = *ak_name_len = 0;
        }
        return r;
}

int attest_activate_credential(const uint8_t *cred, size_t cred_len,
                               const uint8_t *secret, size_t secret_len,
                               uint8_t **challenge, size_t *challenge_len) {
        static const TPMT_SYM_DEF sym_null = { .algorithm = TPM2_ALG_NULL };
        ESYS_CONTEXT *ctx = NULL;
        TSS2_TCTI_CONTEXT *tcti = NULL;
        ESYS_TR ek = ESYS_TR_NONE, ak = ESYS_TR_NONE, policy = ESYS_TR_NONE;
        TPM2B_PUBLIC *ekp = NULL, *akp = NULL;
        TPM2B_ID_OBJECT cred_blob = { 0 };
        TPM2B_ENCRYPTED_SECRET enc_secret = { 0 };
        TPM2B_DIGEST *cert_info = NULL;
        size_t off = 0;
        int r = -EIO;

        *challenge = NULL;
        *challenge_len = 0;
        if (Tss2_MU_TPM2B_ID_OBJECT_Unmarshal(cred, cred_len, &off, &cred_blob) != TSS2_RC_SUCCESS ||
            off != cred_len)
                return -EINVAL;
        off = 0;
        if (Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(secret, secret_len, &off, &enc_secret) != TSS2_RC_SUCCESS ||
            off != secret_len)
                return -EINVAL;

        if ((r = esys_initialize(&ctx, &tcti)) < 0)
                return r;
        r = -EIO;
        if (create_primary(ctx, ESYS_TR_RH_ENDORSEMENT, &ek_template, &ek, &ekp, NULL) < 0 ||
            create_primary(ctx, ESYS_TR_RH_OWNER, &ak_template, &ak, &akp, NULL) < 0)
                goto out;

        /* The EK's auth is a policy: PolicySecret over the endorsement hierarchy. */
        if (Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  NULL, TPM2_SE_POLICY, &sym_null, TPM2_ALG_SHA256, &policy) != TSS2_RC_SUCCESS)
                goto out;
        if (Esys_PolicySecret(ctx, ESYS_TR_RH_ENDORSEMENT, policy,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL, NULL, NULL, 0, NULL, NULL) != TSS2_RC_SUCCESS)
                goto out;

        /* Only a TPM holding both the AK (this name) and the EK can recover the
         * challenge. This proves the AK lives on the same TPM. */
        if (Esys_ActivateCredential(ctx, ak, ek, ESYS_TR_PASSWORD, policy, ESYS_TR_NONE,
                                    &cred_blob, &enc_secret, &cert_info) != TSS2_RC_SUCCESS)
                goto out;
        if (dup_bytes(cert_info->buffer, cert_info->size, challenge, challenge_len) < 0) {
                r = -ENOMEM;
                goto out;
        }
        r = 0;
out:
        Esys_Free(ekp);
        Esys_Free(akp);
        Esys_Free(cert_info);
        if (policy != ESYS_TR_NONE)
                Esys_FlushContext(ctx, policy);
        if (ek != ESYS_TR_NONE)
                Esys_FlushContext(ctx, ek);
        if (ak != ESYS_TR_NONE)
                Esys_FlushContext(ctx, ak);
        esys_finalize(&ctx, &tcti);
        return r;
}
