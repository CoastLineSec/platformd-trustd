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
        return 0;
}
