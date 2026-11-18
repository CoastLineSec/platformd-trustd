/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#include "attest.h"
#include "runtime-event.h"

static void test_runtime_record(uint8_t value[32]) {
        RuntimeTimestamp timestamp = {
                .boot_id = SD_ID128_MAKE(01,23,45,67,89,ab,cd,ef,01,23,45,67,89,ab,cd,ef),
                .boottime_usec = 123,
                .realtime_usec = 456,
        };
        sd_json_variant *payload = NULL;
        uint8_t digest[32], expected[32], previous[32];
        char *record = NULL;

        assert(sd_json_buildo(&payload,
                             SD_JSON_BUILD_PAIR_STRING("sessionId", "test-session"),
                             SD_JSON_BUILD_PAIR_STRING("result", "failure")) >= 0);
        assert(runtime_event_format(&timestamp, "authentication", "io.platformd.Trust.SubmitAuthEvent",
                                    "declared", payload, &record) == 0);
        memcpy(previous, value, sizeof previous);
        assert(runtime_event_digest(record, digest) == 0);
        assert(runtime_event_replay(previous, record, expected) == 0);
        assert(attest_nv_extend(digest, sizeof digest, value) == 0);
        assert(memcmp(value, expected, sizeof expected) == 0);
        assert(attest_nv_read(previous) == 0);
        assert(memcmp(value, previous, sizeof previous) == 0);
        free(record);
        sd_json_variant_unref(payload);
}

static void test_certificate(void) {
        const TPM2B_AUTH auth = {};
        const TPM2B_NV_PUBLIC public = {
                .nvPublic = {
                        .nvIndex = 0x01C0000A,
                        .nameAlg = TPM2_ALG_SHA256,
                        .attributes = TPMA_NV_OWNERREAD | TPMA_NV_OWNERWRITE,
                        .dataSize = 2048,
                },
        };
        ESYS_CONTEXT *context = NULL;
        TSS2_TCTI_CONTEXT *tcti = NULL;
        ESYS_TR nv = ESYS_TR_NONE;
        uint8_t certificate[2048], *ek = NULL, *cert = NULL, *ak = NULL, *name = NULL;
        size_t ek_size, cert_size, ak_size, name_size;

        for (size_t i = 0; i < sizeof certificate; i++)
                certificate[i] = i % 251;
        assert(Tss2_TctiLdr_Initialize(getenv("TSS2_TCTI"), &tcti) == TSS2_RC_SUCCESS);
        assert(Esys_Initialize(&context, tcti, NULL) == TSS2_RC_SUCCESS);
        assert(Esys_NV_DefineSpace(context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                   &auth, &public, &nv) == TSS2_RC_SUCCESS);
        for (size_t offset = 0; offset < sizeof certificate; offset += 512) {
                TPM2B_MAX_NV_BUFFER data = { .size = 512 };

                memcpy(data.buffer, certificate + offset, data.size);
                assert(Esys_NV_Write(context, ESYS_TR_RH_OWNER, nv, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                     ESYS_TR_NONE, &data, offset) == TSS2_RC_SUCCESS);
        }
        assert(attest_get_enrollment(&ek, &ek_size, &cert, &cert_size, &ak, &ak_size, &name, &name_size) == 0);
        assert(ek_size > 0 && ak_size > 0 && name_size > 0);
        assert(cert_size == sizeof certificate && memcmp(cert, certificate, cert_size) == 0);
        assert(Esys_NV_UndefineSpace(context, ESYS_TR_RH_OWNER, nv, ESYS_TR_PASSWORD,
                                     ESYS_TR_NONE, ESYS_TR_NONE) == TSS2_RC_SUCCESS);
        free(ek);
        free(cert);
        free(ak);
        free(name);
        Esys_Finalize(&context);
        Tss2_TctiLdr_Finalize(&tcti);
}

static void test_activation_rejected(const uint8_t *credential, size_t credential_size,
                                     const uint8_t *secret, size_t secret_size, int expected) {
        uint8_t *challenge = NULL;
        size_t challenge_size = 0;

        assert(attest_activate_credential(credential, credential_size, secret, secret_size,
                                          &challenge, &challenge_size) == expected);
        assert(!challenge && challenge_size == 0);
}

static void test_activation(void) {
        const TPM2B_DIGEST expected = {
                .size = 32,
                .buffer = { 0x23, 0x91, 0x84, 0x6c, 0x72, 0xde, 0x5a, 0x08 },
        };
        ESYS_CONTEXT *context = NULL;
        TSS2_TCTI_CONTEXT *tcti = NULL;
        ESYS_TR external = ESYS_TR_NONE;
        TPM2B_PUBLIC public;
        TPM2B_NAME name = {};
        uint8_t *ek = NULL, *cert = NULL, *ak = NULL, *ak_name = NULL;
        size_t ek_size, cert_size, ak_size, name_size, offset = 0;

        assert(attest_get_enrollment(&ek, &ek_size, &cert, &cert_size, &ak, &ak_size,
                                     &ak_name, &name_size) == 0);
        assert(Tss2_MU_TPM2B_PUBLIC_Unmarshal(ek, ek_size, &offset, &public) == TSS2_RC_SUCCESS);
        assert(offset == ek_size);
        assert(name_size > 0 && name_size <= sizeof name.name);
        name.size = name_size;
        memcpy(name.name, ak_name, name_size);

        assert(Tss2_TctiLdr_Initialize(getenv("TSS2_TCTI"), &tcti) == TSS2_RC_SUCCESS);
        assert(Esys_Initialize(&context, tcti, NULL) == TSS2_RC_SUCCESS);
        assert(Esys_SetTimeout(context, 2000) == TSS2_RC_SUCCESS);
        assert(Esys_LoadExternal(context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                 NULL, &public, ESYS_TR_RH_NULL, &external) == TSS2_RC_SUCCESS);

        for (unsigned wrong_name = 0; wrong_name < 2; wrong_name++) {
                TPM2B_ID_OBJECT *credential = NULL;
                TPM2B_ENCRYPTED_SECRET *secret = NULL;
                uint8_t credential_buffer[sizeof(TPM2B_ID_OBJECT) + 1],
                        secret_buffer[sizeof(TPM2B_ENCRYPTED_SECRET) + 1], *challenge = NULL;
                size_t credential_size = 0, secret_size = 0, challenge_size = 0;

                if (wrong_name)
                        name.name[name.size - 1] ^= 1;
                assert(Esys_MakeCredential(context, external, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                           &expected, &name, &credential, &secret) == TSS2_RC_SUCCESS);
                assert(Tss2_MU_TPM2B_ID_OBJECT_Marshal(credential, credential_buffer, sizeof credential_buffer,
                                                      &credential_size) == TSS2_RC_SUCCESS);
                assert(Tss2_MU_TPM2B_ENCRYPTED_SECRET_Marshal(secret, secret_buffer, sizeof secret_buffer,
                                                             &secret_size) == TSS2_RC_SUCCESS);
                assert(credential_size > 0 && credential_size < sizeof credential_buffer);
                assert(secret_size > 0 && secret_size < sizeof secret_buffer);
                Esys_Free(credential);
                Esys_Free(secret);

                if (wrong_name) {
                        test_activation_rejected(credential_buffer, credential_size, secret_buffer, secret_size, -EIO);
                        continue;
                }

                assert(attest_activate_credential(credential_buffer, credential_size, secret_buffer, secret_size,
                                                  &challenge, &challenge_size) == 0);
                assert(challenge_size == expected.size);
                assert(memcmp(challenge, expected.buffer, challenge_size) == 0);
                free(challenge);

                for (size_t i = 0; i < credential_size; i++)
                        test_activation_rejected(credential_buffer, i, secret_buffer, secret_size, -EINVAL);
                for (size_t i = 0; i < secret_size; i++)
                        test_activation_rejected(credential_buffer, credential_size, secret_buffer, i, -EINVAL);

                credential_buffer[credential_size] = 0;
                test_activation_rejected(credential_buffer, credential_size + 1, secret_buffer, secret_size, -EINVAL);
                secret_buffer[secret_size] = 0;
                test_activation_rejected(credential_buffer, credential_size, secret_buffer, secret_size + 1, -EINVAL);

                credential_buffer[credential_size - 1] ^= 1;
                test_activation_rejected(credential_buffer, credential_size, secret_buffer, secret_size, -EIO);
        }

        assert(Esys_FlushContext(context, external) == TSS2_RC_SUCCESS);
        Esys_Finalize(&context);
        Tss2_TctiLdr_Finalize(&tcti);
        free(ek);
        free(cert);
        free(ak);
        free(ak_name);
}

int main(int argc, char **argv) {
        static const uint8_t nonce[] = { 1, 2, 3, 4 };
        uint8_t value[32], digest[32], input[36] = {}, *ak = NULL, *info = NULL, *signature = NULL, *public = NULL;
        size_t ak_size, info_size, signature_size, public_size, offset = 0;
        const char *tcti = getenv("TSS2_TCTI");
        TPM2B_NV_PUBLIC nv;
        TPMS_ATTEST certified;

        assert(tcti && strncmp(tcti, "swtpm:path=/tmp/", 16) == 0);
        assert(argc == 2);
        if (strcmp(argv[1], "conflict") == 0) {
                assert(attest_nv_initialize() == -EKEYREJECTED);
                assert(attest_nv_read(value) == -EKEYREJECTED);
                assert(attest_nv_extend(nonce, sizeof nonce, value) == -EKEYREJECTED);
                assert(attest_nv_certify(nonce, sizeof nonce, &ak, &ak_size,
                                         &info, &info_size, &signature, &signature_size) == -EKEYREJECTED);
                return 0;
        }
        if (strcmp(argv[1], "unauthorized") == 0) {
                assert(attest_nv_read(value) < 0);
                assert(attest_nv_extend(nonce, sizeof nonce, value) < 0);
                return 0;
        }
        assert(strcmp(argv[1], "valid") == 0);
        assert(attest_nv_read(value) == -ENOENT);
        assert(attest_nv_initialize() == 0);
        assert(attest_nv_initialize() == 0);
        assert(attest_nv_read(value) == 0);
        assert(memcmp(value, input, sizeof value) == 0);
        memcpy(input + 32, nonce, sizeof nonce);
        assert(EVP_Q_digest(NULL, "SHA256", NULL, input, sizeof input, digest, NULL));
        assert(attest_nv_extend(nonce, sizeof nonce, value) == 0);
        assert(memcmp(value, digest, sizeof value) == 0);
        test_runtime_record(value);
        assert(attest_nv_public(&public, &public_size) == 0);
        assert(Tss2_MU_TPM2B_NV_PUBLIC_Unmarshal(public, public_size, &offset, &nv) == TSS2_RC_SUCCESS);
        assert(offset == public_size);
        assert((nv.nvPublic.attributes & TPMA_NV_TPM2_NT_MASK) == (TPM2_NT_EXTEND << TPMA_NV_TPM2_NT_SHIFT));
        assert(attest_nv_certify(nonce, sizeof nonce, &ak, &ak_size,
                                 &info, &info_size, &signature, &signature_size) == 0);
        offset = 0;
        assert(Tss2_MU_TPMS_ATTEST_Unmarshal(info, info_size, &offset, &certified) == TSS2_RC_SUCCESS);
        assert(offset == info_size && certified.type == TPM2_ST_ATTEST_NV);
        assert(certified.extraData.size == sizeof nonce);
        assert(memcmp(certified.extraData.buffer, nonce, sizeof nonce) == 0);
        assert(certified.attested.nv.nvContents.size == sizeof value);
        assert(memcmp(certified.attested.nv.nvContents.buffer, value, sizeof value) == 0);
        free(public);
        free(ak);
        free(info);
        free(signature);
        test_certificate();
        test_activation();
        return 0;
}
