/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "attestation-appraise.h"

#define PHASE "enter-initrd:leave-initrd:sysinit:ready"

typedef struct Fixture {
        sd_json_variant *token;
        char *ak;
        char *nonce;
        char pcr11[65];
} Fixture;

static unsigned accepted_references, rejected_references;

static char *read_fixture_file(int dirfd, const char *name) {
        char *buffer = malloc(65537);
        ssize_t n;
        size_t size = 0;
        int fd;

        assert(buffer);
        fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        assert(fd >= 0);
        while ((n = read(fd, buffer + size, 65537 - size)) != 0) {
                if (n < 0 && errno == EINTR)
                        continue;
                assert(n > 0);
                size += (size_t) n;
                assert(size <= 65536);
        }
        buffer[size] = 0;
        assert(close(fd) == 0);
        return buffer;
}

static Fixture fixture_new(const char *executable) {
        char directory[] = "/tmp/platformd-attestation-appraise.XXXXXX";
        char *text;
        Fixture f = {};
        pid_t pid;
        int dirfd, status;

        assert(mkdtemp(directory));
        pid = fork();
        assert(pid >= 0);
        if (pid == 0) {
                execl(executable, executable, "--write-fixture", directory, NULL);
                _exit(127);
        }
        while (waitpid(pid, &status, 0) < 0)
                assert(errno == EINTR);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        assert(dirfd >= 0);
        text = read_fixture_file(dirfd, "token.json");
        assert(sd_json_parse(text, 0, &f.token, NULL, NULL) >= 0);
        free(text);
        f.ak = read_fixture_file(dirfd, "ak.hex");
        f.nonce = read_fixture_file(dirfd, "nonce.hex");
        for (unsigned i = 0; i < 32; i++)
                assert(snprintf(f.pcr11 + 2 * i, 3, "%02x", 11 * 17 + i) == 2);
        assert(unlinkat(dirfd, "token.json", 0) == 0);
        assert(unlinkat(dirfd, "ak.hex", 0) == 0);
        assert(unlinkat(dirfd, "nonce.hex", 0) == 0);
        assert(close(dirfd) == 0);
        assert(rmdir(directory) == 0);
        return f;
}

static void fixture_done(Fixture *f) {
        sd_json_variant_unref(f->token);
        free(f->ak);
        free(f->nonce);
}

static sd_json_variant *candidate_new(const char *phase, const char *hash) {
        sd_json_variant *candidate = NULL;

        assert(sd_json_buildo(&candidate,
                             SD_JSON_BUILD_PAIR_STRING("phase", phase),
                             SD_JSON_BUILD_PAIR_UNSIGNED("pcr", 11),
                             SD_JSON_BUILD_PAIR_STRING("hash", hash)) >= 0);
        return candidate;
}

static sd_json_variant *reference_new(const char *phase, const char *hash) {
        sd_json_variant *candidate = candidate_new(phase, hash), *array = NULL, *reference = NULL;

        assert(sd_json_variant_append_array(&array, candidate) >= 0);
        assert(sd_json_buildo(&reference, SD_JSON_BUILD_PAIR_VARIANT("sha256", array)) >= 0);
        sd_json_variant_unref(candidate);
        sd_json_variant_unref(array);
        return reference;
}

static sd_json_variant *accepted(const Fixture *f, sd_json_variant *reference, const char *phase) {
        static const char *const checks[] = {
                "expectedKeyMatched", "nonceMatched", "quoteSignatureVerified", "nvSignatureVerified",
                "pcrDigestVerified", "nvPublicVerified", "runtimeReplayVerified", "approvedPcr11Matched",
        };
        static const char *const excluded[] = {
                "enrolled", "approvedBoot", "authenticated", "authenticationFresh", "policySatisfied",
                "secureBoot", "machineId",
        };
        sd_json_variant *report = NULL;

        assert(attestation_appraise(f->token, f->ak, f->nonce, reference, phase, &report) == 0);
        assert(sd_json_variant_is_object(report));
        assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(report, "profile")),
                      "io.platformd.Trust.AttestationAppraisal.v1") == 0);
        assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(report, "approvedPhase")), phase) == 0);
        assert(sd_json_variant_unsigned(sd_json_variant_by_key(report, "retainedEvents")) == 3);
        for (size_t i = 0; i < sizeof checks / sizeof checks[0]; i++) {
                sd_json_variant *v = sd_json_variant_by_key(report, checks[i]);

                assert(sd_json_variant_is_boolean(v) && sd_json_variant_boolean(v));
        }
        for (size_t i = 0; i < sizeof excluded / sizeof excluded[0]; i++)
                assert(!sd_json_variant_by_key(report, excluded[i]));
        accepted_references++;
        return report;
}

static void rejected(const Fixture *f, sd_json_variant *reference, const char *phase) {
        sd_json_variant *report = NULL;

        assert(attestation_appraise(f->token, f->ak, f->nonce, reference, phase, &report) < 0);
        assert(!report);
        rejected_references++;
}

static void test_positive(const Fixture *f) {
        static const char *const phases[] = { PHASE, "custom:stage.2-ready", "custom phase:ready" };
        char upper[65];

        for (unsigned i = 0; i < 32; i++)
                assert(snprintf(upper + 2 * i, 3, "%02X", 11 * 17 + i) == 2);
        for (size_t i = 0; i < sizeof phases / sizeof phases[0]; i++) {
                sd_json_variant *reference = reference_new(phases[i], f->pcr11);
                sd_json_variant *report = accepted(f, reference, phases[i]);

                sd_json_variant_unref(reference);
                sd_json_variant_unref(report);
                reference = reference_new(phases[i], upper);
                report = accepted(f, reference, phases[i]);
                sd_json_variant_unref(reference);
                sd_json_variant_unref(report);
        }
}

static void test_candidates(const Fixture *f) {
        sd_json_variant *reference = NULL, *array = NULL, *report;
        sd_json_variant *good = candidate_new(PHASE, f->pcr11);
        sd_json_variant *other_phase = candidate_new("enter-initrd", f->pcr11);
        sd_json_variant *other_hash = candidate_new(PHASE, "0000000000000000000000000000000000000000000000000000000000000000");

        assert(sd_json_variant_append_array(&array, other_phase) >= 0);
        assert(sd_json_variant_append_array(&array, other_hash) >= 0);
        assert(sd_json_buildo(&reference, SD_JSON_BUILD_PAIR_VARIANT("sha256", array)) >= 0);
        rejected(f, reference, PHASE);
        reference = sd_json_variant_unref(reference);
        assert(sd_json_variant_append_array(&array, good) >= 0);
        assert(sd_json_buildo(&reference, SD_JSON_BUILD_PAIR_VARIANT("sha256", array)) >= 0);
        report = accepted(f, reference, PHASE);
        sd_json_variant_unref(report);
        reference = sd_json_variant_unref(reference);
        assert(sd_json_variant_set_field_unsigned(&other_phase, "pcr", 7) >= 0);
        assert(sd_json_variant_append_array(&array, other_phase) >= 0);
        assert(sd_json_buildo(&reference, SD_JSON_BUILD_PAIR_VARIANT("sha256", array)) >= 0);
        rejected(f, reference, PHASE);
        sd_json_variant_unref(good);
        sd_json_variant_unref(other_phase);
        sd_json_variant_unref(other_hash);
        sd_json_variant_unref(array);
        sd_json_variant_unref(reference);
}

static void test_schema(const Fixture *f) {
        static const char *const malformed[] = {
                "null", "false", "[]", "{}", "{\"sha256\":null}", "{\"sha256\":{}}", "{\"sha256\":[]}",
                "{\"sha256\":[null]}", "{\"sha256\":[[]]}", "{\"sha256\":[{}]}",
                "{\"sha1\":[{\"phase\":\"" PHASE "\",\"pcr\":11,\"hash\":\"%s\"}]}",
                "{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":11,\"hash\":\"%s\"}],\"sha1\":[]}",
                "{\"sha256\":[],\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":11,\"hash\":\"%s\"}]}",
                "{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":11,\"pcr\":11,\"hash\":\"%s\"}]}",
                "{\"sha256\":[{\"phase\":\"" PHASE "\",\"phase\":\"" PHASE "\",\"pcr\":11,\"hash\":\"%s\"}]}",
                "{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":11,\"hash\":\"%s\",\"hash\":\"00\"}]}",
                "{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":11,\"hash\":\"%s\",\"approved\":true}]}",
                "{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":11.0,\"hash\":\"%s\"}]}",
                "{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":\"11\",\"hash\":\"%s\"}]}",
                "{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":-1,\"hash\":\"%s\"}]}",
                "{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":12,\"hash\":\"%s\"}]}",
                "{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":true,\"hash\":\"%s\"}]}",
                "{\"sha256\":[{\"pcr\":11,\"hash\":\"%s\"}]}",
                "{\"sha256\":[{\"phase\":false,\"pcr\":11,\"hash\":\"%s\"}]}",
                "{\"sha256\":[{\"phase\":\"\",\"pcr\":11,\"hash\":\"%s\"}]}",
                "{\"sha256\":[{\"phase\":\"ready\\n\",\"pcr\":11,\"hash\":\"%s\"}]}",
                "{\"sha256\":[{\"phase\":\"ready\\u007f\",\"pcr\":11,\"hash\":\"%s\"}]}",
                "{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":11,\"hash\":null}]}",
                "{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":11,\"hash\":\"\"}]}",
                "{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":11,\"hash\":\"0x%s\"}]}",
        };

        rejected(f, NULL, PHASE);
        for (size_t i = 0; i < sizeof malformed / sizeof malformed[0]; i++) {
                sd_json_variant *reference = NULL;
                char text[512];
                int n;

                n = snprintf(text, sizeof text, malformed[i], f->pcr11);
                assert(n > 0 && (size_t) n < sizeof text);
                assert(sd_json_parse(text, 0, &reference, NULL, NULL) >= 0);
                rejected(f, reference, PHASE);
                sd_json_variant_unref(reference);
        }
}

static void test_bounds(const Fixture *f) {
        sd_json_variant *reference, *array = NULL, *candidate, *report;
        char phase[1026], hash[67];

        reference = reference_new(PHASE, f->pcr11);
        rejected(f, reference, NULL);
        rejected(f, reference, "");
        rejected(f, reference, "ready\n");
        rejected(f, reference, "ready\177");
        rejected(f, reference, "ready");
        memset(phase, 'x', sizeof phase - 1);
        phase[sizeof phase - 1] = 0;
        rejected(f, reference, phase);
        sd_json_variant_unref(reference);
        reference = reference_new(phase, f->pcr11);
        rejected(f, reference, PHASE);
        sd_json_variant_unref(reference);
        memcpy(hash, f->pcr11, 65);
        hash[63] = 0;
        reference = reference_new(PHASE, hash);
        rejected(f, reference, PHASE);
        sd_json_variant_unref(reference);
        memcpy(hash, f->pcr11, 65);
        hash[64] = '0';
        hash[65] = 0;
        reference = reference_new(PHASE, hash);
        rejected(f, reference, PHASE);
        sd_json_variant_unref(reference);
        hash[64] = 0;
        hash[0] = 'g';
        reference = reference_new(PHASE, hash);
        rejected(f, reference, PHASE);
        sd_json_variant_unref(reference);
        candidate = candidate_new(PHASE, f->pcr11);
        for (unsigned i = 0; i < 1024; i++)
                assert(sd_json_variant_append_array(&array, candidate) >= 0);
        assert(sd_json_buildo(&reference, SD_JSON_BUILD_PAIR_VARIANT("sha256", array)) >= 0);
        report = accepted(f, reference, PHASE);
        sd_json_variant_unref(report);
        sd_json_variant_unref(reference);
        assert(sd_json_variant_append_array(&array, candidate) >= 0);
        assert(sd_json_buildo(&reference, SD_JSON_BUILD_PAIR_VARIANT("sha256", array)) >= 0);
        rejected(f, reference, PHASE);
        sd_json_variant_unref(reference);
        sd_json_variant_unref(candidate);
        array = sd_json_variant_unref(array);
        phase[1024] = 0;
        reference = reference_new(phase, f->pcr11);
        report = accepted(f, reference, phase);
        sd_json_variant_unref(report);
        sd_json_variant_unref(reference);
        candidate = candidate_new(phase, f->pcr11);
        for (unsigned i = 0; i < 1024; i++)
                assert(sd_json_variant_append_array(&array, candidate) >= 0);
        assert(sd_json_buildo(&reference, SD_JSON_BUILD_PAIR_VARIANT("sha256", array)) >= 0);
        rejected(f, reference, phase);
        sd_json_variant_unref(candidate);
        sd_json_variant_unref(array);
        sd_json_variant_unref(reference);
}

static void test_trust_boundary(const Fixture *original) {
        Fixture f = *original;
        sd_json_variant *reference = reference_new(PHASE, f.pcr11), *before, *after, *local = NULL;

        f.token = sd_json_variant_ref(original->token);
        before = accepted(&f, reference, PHASE);
        f.nonce = "00";
        rejected(&f, reference, PHASE);
        f.nonce = original->nonce;
        f.ak = "00";
        rejected(&f, reference, PHASE);
        f.ak = original->ak;
        assert(sd_json_buildo(&local,
                             SD_JSON_BUILD_PAIR_STRING("machineId", "unverified"),
                             SD_JSON_BUILD_PAIR_STRING("secureBoot", "enabled"),
                             SD_JSON_BUILD_PAIR_UNSIGNED("realtimeUSec", UINT64_MAX)) >= 0);
        assert(sd_json_variant_set_field(&f.token, "localAssertions", local) >= 0);
        after = accepted(&f, reference, PHASE);
        assert(sd_json_variant_equal(before, after));
        sd_json_variant_unref(after);
        sd_json_variant_unref(before);
        sd_json_variant_unref(local);
        assert(sd_json_variant_set_field(&f.token, "reference", reference) >= 0);
        rejected(&f, reference, PHASE);
        sd_json_variant_unref(f.token);
        f.token = NULL;
        assert(sd_json_buildo(&f.token,
                             SD_JSON_BUILD_PAIR_BOOLEAN("quoteSignatureVerified", true),
                             SD_JSON_BUILD_PAIR_BOOLEAN("pcrDigestVerified", true)) >= 0);
        rejected(&f, reference, PHASE);
        sd_json_variant_unref(f.token);
        sd_json_variant_unref(reference);
}

static void test_unverified_pcr(const Fixture *original) {
        static const char zero[] = "0000000000000000000000000000000000000000000000000000000000000000";
        Fixture f = *original;
        sd_json_variant *measurements = sd_json_variant_by_key(f.token, "measurements");
        sd_json_variant *boot = sd_json_variant_ref(sd_json_variant_by_index(measurements, 1));
        sd_json_variant *pcrs = sd_json_variant_by_key(boot, "pcrs"), *pcr, *array = NULL, *reference;
        sd_json_variant *pcr_items[16], *measurement_items[3];

        f.token = sd_json_variant_ref(original->token);
        pcr = sd_json_variant_ref(sd_json_variant_by_index(pcrs, 11));
        assert(sd_json_variant_set_field_string(&pcr, "sha256", zero) >= 0);
        for (size_t i = 0; i < 16; i++)
                pcr_items[i] = i == 11 ? pcr : sd_json_variant_by_index(pcrs, i);
        assert(sd_json_variant_new_array(&array, pcr_items, 16) >= 0);
        assert(sd_json_variant_set_field(&boot, "pcrs", array) >= 0);
        array = sd_json_variant_unref(array);
        for (size_t i = 0; i < 3; i++)
                measurement_items[i] = i == 1 ? boot : sd_json_variant_by_index(measurements, i);
        assert(sd_json_variant_new_array(&array, measurement_items, 3) >= 0);
        assert(sd_json_variant_set_field(&f.token, "measurements", array) >= 0);
        reference = reference_new(PHASE, zero);
        rejected(&f, reference, PHASE);
        sd_json_variant_unref(reference);
        sd_json_variant_unref(array);
        sd_json_variant_unref(pcr);
        sd_json_variant_unref(boot);
        sd_json_variant_unref(f.token);
}

int main(int argc, char **argv) {
        Fixture f;

        assert(argc == 2);
        f = fixture_new(argv[1]);
        test_positive(&f);
        test_candidates(&f);
        test_schema(&f);
        test_bounds(&f);
        test_trust_boundary(&f);
        test_unverified_pcr(&f);
        fixture_done(&f);
        printf("Accepted %u approved references; rejected %u invalid appraisals.\n", accepted_references, rejected_references);
        return 0;
}
