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
#include "attestation-request.h"

#define PHASE "enter-initrd:leave-initrd:sysinit:ready"
#define CHALLENGE "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#define AUDIENCE "https://service.example"
#define OPERATION "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define CONTEXT "{\"challengeHex\":\"" CHALLENGE "\",\"audience\":\"" AUDIENCE "\",\"operationDigestHex\":\"" OPERATION "\"}"
#define REQUEST "{\"uid\":1000,\"sessionId\":\"fixture-session\",\"context\":" CONTEXT "}"
#define PCR11 "bbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9da"

typedef struct Fixture {
        sd_json_variant *token;
        char *ak;
} Fixture;

static unsigned accepted_requests, rejected_requests;

static sd_json_variant *parse(const char *text) {
        sd_json_variant *value = NULL;

        assert(sd_json_parse(text, 0, &value, NULL, NULL) >= 0);
        return value;
}

static char *read_fixture_file(int dirfd, const char *name) {
        char *buffer = malloc(65537);
        size_t size = 0;
        int fd;

        assert(buffer);
        fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        assert(fd >= 0);
        for (;;) {
                ssize_t n = read(fd, buffer + size, 65537 - size);

                if (n < 0 && errno == EINTR)
                        continue;
                assert(n >= 0);
                if (n == 0)
                        break;
                size += (size_t) n;
                assert(size <= 65536);
        }
        buffer[size] = 0;
        assert(close(fd) == 0);
        return buffer;
}

static Fixture fixture_new(const char *executable, const char *mode) {
        char directory[] = "/tmp/platformd-attestation-request.XXXXXX";
        char *text;
        Fixture f = {};
        pid_t pid;
        int dirfd, status;

        assert(mkdtemp(directory));
        pid = fork();
        assert(pid >= 0);
        if (pid == 0) {
                execl(executable, executable, mode, directory, NULL);
                _exit(127);
        }
        while (waitpid(pid, &status, 0) < 0)
                assert(errno == EINTR);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        assert(dirfd >= 0);
        text = read_fixture_file(dirfd, "token.json");
        f.token = parse(text);
        free(text);
        f.ak = read_fixture_file(dirfd, "ak.hex");
        text = read_fixture_file(dirfd, "nonce.hex");
        assert(strcmp(text, CHALLENGE) == 0);
        free(text);
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
}

static sd_json_variant *reference_new(void) {
        return parse("{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":11,\"hash\":\"" PCR11 "\"}]}");
}

static void accepted(const Fixture *f, sd_json_variant *request, sd_json_variant *reference) {
        static const char *const checks[] = {
                "expectedKeyMatched", "nonceMatched", "quoteSignatureVerified", "nvSignatureVerified",
                "pcrDigestVerified", "nvPublicVerified", "runtimeReplayVerified", "approvedPcr11Matched",
                "authenticationDeclarationMatched",
        };
        static const char *const excluded[] = {
                "enrolled", "approvedBoot", "authenticated", "authenticationFresh", "policySatisfied",
                "secureBoot", "machineId", "challengeConsumed", "requestAccepted",
        };
        sd_json_variant *report = NULL;

        assert(attestation_appraise_request(f->token, f->ak, request, reference, PHASE, &report) == 0);
        assert(sd_json_variant_is_object(report));
        assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(report, "profile")),
                      "io.platformd.Trust.RequestAppraisal.v1") == 0);
        assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(report, "approvedPhase")), PHASE) == 0);
        assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(report, "authenticationQuality")), "root-declared") == 0);
        assert(sd_json_variant_unsigned(sd_json_variant_by_key(report, "retainedEvents")) == 3);
        assert(sd_json_variant_equal(sd_json_variant_by_key(report, "request"), request));
        for (size_t i = 0; i < sizeof checks / sizeof checks[0]; i++) {
                sd_json_variant *value = sd_json_variant_by_key(report, checks[i]);

                assert(sd_json_variant_is_boolean(value) && sd_json_variant_boolean(value));
        }
        for (size_t i = 0; i < sizeof excluded / sizeof excluded[0]; i++)
                assert(!sd_json_variant_by_key(report, excluded[i]));
        accepted_requests++;
        sd_json_variant_unref(report);
}

static void rejected(const Fixture *f, sd_json_variant *request, sd_json_variant *reference) {
        sd_json_variant *report = (sd_json_variant *) UINTPTR_MAX;

        assert(attestation_appraise_request(f->token, f->ak, request, reference, PHASE, &report) < 0);
        assert(!report);
        rejected_requests++;
}

static void test_schema(const Fixture *f, sd_json_variant *reference) {
        static const char *const cases[] = {
                "null", "false", "[]", "{}",
                "{\"sessionId\":\"fixture-session\",\"context\":" CONTEXT "}",
                "{\"uid\":1000,\"context\":" CONTEXT "}",
                "{\"uid\":1000,\"sessionId\":\"fixture-session\"}",
                "{\"uid\":1000,\"sessionId\":\"fixture-session\",\"context\":" CONTEXT ",\"approved\":true}",
                "{\"uid\":1000,\"uid\":1000,\"sessionId\":\"fixture-session\",\"context\":" CONTEXT "}",
                "{\"uid\":1000,\"uid\":1000,\"context\":" CONTEXT "}",
                "{\"uid\":null,\"sessionId\":\"fixture-session\",\"context\":" CONTEXT "}",
                "{\"uid\":false,\"sessionId\":\"fixture-session\",\"context\":" CONTEXT "}",
                "{\"uid\":1000.0,\"sessionId\":\"fixture-session\",\"context\":" CONTEXT "}",
                "{\"uid\":-1,\"sessionId\":\"fixture-session\",\"context\":" CONTEXT "}",
                "{\"uid\":4294967295,\"sessionId\":\"fixture-session\",\"context\":" CONTEXT "}",
                "{\"uid\":18446744073709551615,\"sessionId\":\"fixture-session\",\"context\":" CONTEXT "}",
                "{\"uid\":\"1000\",\"sessionId\":\"fixture-session\",\"context\":" CONTEXT "}",
                "{\"uid\":1000,\"sessionId\":null,\"context\":" CONTEXT "}",
                "{\"uid\":1000,\"sessionId\":false,\"context\":" CONTEXT "}",
                "{\"uid\":1000,\"sessionId\":\"\",\"context\":" CONTEXT "}",
                "{\"uid\":1000,\"sessionId\":\"fixture-session\\n\",\"context\":" CONTEXT "}",
                "{\"uid\":1000,\"sessionId\":\"fixture-session\\u007f\",\"context\":" CONTEXT "}",
                "{\"uid\":1000,\"sessionId\":\"fixture-session\\u0080\",\"context\":" CONTEXT "}",
                "{\"uid\":1000,\"sessionId\":\"fixture-session\",\"context\":null}",
                "{\"uid\":1000,\"sessionId\":\"fixture-session\",\"context\":[]}",
                "{\"uid\":1000,\"sessionId\":\"fixture-session\",\"context\":{}}",
                "{\"uid\":1000,\"sessionId\":\"fixture-session\",\"context\":{\"challengeHex\":\"" CHALLENGE "\",\"challengeHex\":\"" CHALLENGE "\",\"operationDigestHex\":\"" OPERATION "\"}}",
                "{\"uid\":1000,\"sessionId\":\"fixture-session\",\"context\":{\"challengeHex\":\"" CHALLENGE "\",\"audience\":\"" AUDIENCE "\",\"audience\":\"" AUDIENCE "\",\"operationDigestHex\":\"" OPERATION "\"}}",
                "{\"uid\":1000,\"sessionId\":\"fixture-session\",\"context\":{\"challengeHex\":\"" CHALLENGE "\",\"audience\":\"" AUDIENCE "\",\"operationDigestHex\":\"" OPERATION "\",\"verified\":true}}",
        };

        rejected(f, NULL, reference);
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
                sd_json_variant *request = parse(cases[i]);

                rejected(f, request, reference);
                sd_json_variant_unref(request);
        }
}

static void test_context(const Fixture *f, sd_json_variant *reference) {
        static const char *const names[] = { "challengeHex", "audience", "operationDigestHex" };
        static const char *const invalid_hex[] = {
                "", "a", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1",
                CHALLENGE "0", "G00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        };
        static const char *const audiences[] = { "", "https://service.example\n", "\177", "\303\251", "https://other.example" };
        sd_json_variant *request, *context;
        char large[258];

        for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
                request = parse(REQUEST);
                context = parse(CONTEXT);
                assert(sd_json_variant_set_field_boolean(&context, names[i], true) >= 0);
                assert(sd_json_variant_set_field(&request, "context", context) >= 0);
                rejected(f, request, reference);
                sd_json_variant_unref(request);
                sd_json_variant_unref(context);
        }
        for (size_t i = 0; i < sizeof invalid_hex / sizeof invalid_hex[0]; i++)
                for (unsigned j = 0; j < 2; j++) {
                        request = parse(REQUEST);
                        context = parse(CONTEXT);
                        assert(sd_json_variant_set_field_string(&context, names[j * 2], invalid_hex[i]) >= 0);
                        assert(sd_json_variant_set_field(&request, "context", context) >= 0);
                        rejected(f, request, reference);
                        sd_json_variant_unref(request);
                        sd_json_variant_unref(context);
                }
        for (size_t i = 0; i < sizeof audiences / sizeof audiences[0]; i++) {
                request = parse(REQUEST);
                context = parse(CONTEXT);
                assert(sd_json_variant_set_field_string(&context, "audience", audiences[i]) >= 0);
                assert(sd_json_variant_set_field(&request, "context", context) >= 0);
                rejected(f, request, reference);
                sd_json_variant_unref(request);
                sd_json_variant_unref(context);
        }
        memset(large, 'x', sizeof large - 1);
        large[sizeof large - 1] = 0;
        request = parse(REQUEST);
        assert(sd_json_variant_set_field_string(&request, "sessionId", large) >= 0);
        rejected(f, request, reference);
        sd_json_variant_unref(request);
        request = parse(REQUEST);
        context = parse(CONTEXT);
        assert(sd_json_variant_set_field_string(&context, "audience", large) >= 0);
        assert(sd_json_variant_set_field(&request, "context", context) >= 0);
        rejected(f, request, reference);
        sd_json_variant_unref(request);
        sd_json_variant_unref(context);

        request = parse(REQUEST);
        assert(sd_json_variant_set_field_unsigned(&request, "uid", 1001) >= 0);
        rejected(f, request, reference);
        sd_json_variant_unref(request);
        request = parse(REQUEST);
        assert(sd_json_variant_set_field_string(&request, "sessionId", "other-session") >= 0);
        rejected(f, request, reference);
        sd_json_variant_unref(request);
        for (unsigned i = 0; i < 2; i++) {
                request = parse(REQUEST);
                context = parse(CONTEXT);
                assert(sd_json_variant_set_field_string(&context, names[i * 2],
                                                       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") >= 0);
                assert(sd_json_variant_set_field(&request, "context", context) >= 0);
                rejected(f, request, reference);
                sd_json_variant_unref(request);
                sd_json_variant_unref(context);
        }
}

static void test_evidence(const Fixture *f, sd_json_variant *request, sd_json_variant *reference) {
        Fixture copy = { .ak = f->ak };
        sd_json_variant *report = NULL, *measurements, *array = NULL, *local;

        assert(attestation_appraise_request(f->token, f->ak, request, reference, PHASE, NULL) == -EINVAL);
        rejected(&copy, request, reference);
        copy.token = parse("{}");
        rejected(&copy, request, reference);
        sd_json_variant_unref(copy.token);
        assert(attestation_appraise(f->token, f->ak, CHALLENGE, reference, PHASE, &copy.token) == 0);
        rejected(&copy, request, reference);
        sd_json_variant_unref(copy.token);
        copy.token = sd_json_variant_ref(f->token);
        copy.ak = NULL;
        rejected(&copy, request, reference);
        copy.ak = "00";
        rejected(&copy, request, reference);
        copy.ak = f->ak;
        rejected(&copy, request, NULL);
        local = parse("{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":11,\"hash\":\"0000000000000000000000000000000000000000000000000000000000000000\"}]}");
        rejected(&copy, request, local);
        sd_json_variant_unref(local);
        assert(attestation_appraise_request(f->token, f->ak, request, reference, "other-phase", &report) < 0 && !report);
        assert(attestation_appraise_request(f->token, f->ak, request, reference, NULL, &report) < 0 && !report);
        local = parse("{\"secureBoot\":\"disabled\",\"machineId\":\"00000000000000000000000000000000\",\"realtimeUSec\":0}");
        assert(sd_json_variant_set_field(&copy.token, "localAssertions", local) >= 0);
        accepted(&copy, request, reference);
        sd_json_variant_unref(local);
        measurements = sd_json_variant_by_key(copy.token, "measurements");
        for (size_t i = sd_json_variant_elements(measurements); i > 0; i--)
                assert(sd_json_variant_append_array(&array, sd_json_variant_by_index(measurements, i - 1)) >= 0);
        assert(sd_json_variant_set_field(&copy.token, "measurements", array) >= 0);
        accepted(&copy, request, reference);
        sd_json_variant_unref(array);
        assert(sd_json_variant_set_field(&copy.token, "request", request) >= 0);
        rejected(&copy, request, reference);
        sd_json_variant_unref(copy.token);
}

static void test_tampered_records(const Fixture *f, sd_json_variant *request, sd_json_variant *reference) {
        for (unsigned mode = 0; mode < 4; mode++) {
                sd_json_variant *measurements = sd_json_variant_by_key(f->token, "measurements"), *array = NULL;
                Fixture copy = { .token = sd_json_variant_ref(f->token), .ak = f->ak };

                for (size_t i = 0; i < sd_json_variant_elements(measurements); i++) {
                        sd_json_variant *measurement = sd_json_variant_ref(sd_json_variant_by_index(measurements, i));
                        const char *type = sd_json_variant_string(sd_json_variant_by_key(measurement, "type"));

                        if (strcmp(type, "nv-runtime-log") == 0) {
                                sd_json_variant *events = sd_json_variant_by_key(measurement, "events"), *changed = NULL;

                                for (size_t j = 0; j < sd_json_variant_elements(events); j++) {
                                        sd_json_variant *event = sd_json_variant_ref(sd_json_variant_by_index(events, j));

                                        if (j == 0) {
                                                sd_json_variant *record = parse(sd_json_variant_string(sd_json_variant_by_key(event, "description")));
                                                sd_json_variant *value = NULL;
                                                char *text = NULL;

                                                if (mode == 0) {
                                                        assert(sd_json_variant_new_null(&value) >= 0);
                                                        assert(sd_json_variant_set_field(&record, "source", value) >= 0);
                                                        sd_json_variant_unref(value);
                                                } else if (mode == 1)
                                                        assert(sd_json_variant_set_field_string(&record, "type", "lock-state") >= 0);
                                                else if (mode == 2)
                                                        assert(sd_json_variant_set_field_string(&record, "source", "io.platformd.Trust.SubmitAuthEvent") >= 0);
                                                else {
                                                        value = sd_json_variant_ref(sd_json_variant_by_key(record, "payload"));
                                                        assert(sd_json_variant_set_field_unsigned(&value, "uid", 1001) >= 0);
                                                        assert(sd_json_variant_set_field(&record, "payload", value) >= 0);
                                                        sd_json_variant_unref(value);
                                                }
                                                assert(sd_json_variant_format(record, 0, &text) >= 0);
                                                assert(sd_json_variant_set_field_string(&event, "description", text) >= 0);
                                                free(text);
                                                sd_json_variant_unref(record);
                                        }
                                        assert(sd_json_variant_append_array(&changed, event) >= 0);
                                        sd_json_variant_unref(event);
                                }
                                assert(sd_json_variant_set_field(&measurement, "events", changed) >= 0);
                                sd_json_variant_unref(changed);
                        }
                        assert(sd_json_variant_append_array(&array, measurement) >= 0);
                        sd_json_variant_unref(measurement);
                }
                assert(sd_json_variant_set_field(&copy.token, "measurements", array) >= 0);
                rejected(&copy, request, reference);
                sd_json_variant_unref(array);
                sd_json_variant_unref(copy.token);
        }
}

static void test_lifecycle(const char *executable, sd_json_variant *request, sd_json_variant *reference) {
        static const struct {
                const char *mode;
                bool accepted;
        } cases[] = {
                { "--write-fixture", false },
                { "--write-context-lock-fixture", false },
                { "--write-context-unknown-fixture", false },
                { "--write-context-sleep-fixture", false },
                { "--write-context-lock-unlock-fixture", false },
                { "--write-context-unlock-fixture", true },
                { "--write-context-other-lock-fixture", true },
                { "--write-lock-context-fixture", true },
                { "--write-sleep-context-fixture", true },
                { "--write-context-sleep-context-fixture", true },
        };

        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
                Fixture f = fixture_new(executable, cases[i].mode);
                sd_json_variant *report = NULL;

                assert(attestation_appraise(f.token, f.ak, CHALLENGE, reference, PHASE, &report) == 0);
                sd_json_variant_unref(report);
                if (cases[i].accepted)
                        accepted(&f, request, reference);
                else
                        rejected(&f, request, reference);
                fixture_done(&f);
        }
}

int main(int argc, char **argv) {
        sd_json_variant *request = parse(REQUEST), *reference = reference_new(), *reordered;
        Fixture f;

        assert(argc == 2);
        f = fixture_new(argv[1], "--write-context-fixture");
        accepted(&f, request, reference);
        accepted(&f, request, reference);
        reordered = parse("{\"context\":{\"operationDigestHex\":\"" OPERATION "\",\"audience\":\"" AUDIENCE "\",\"challengeHex\":\"" CHALLENGE "\"},\"sessionId\":\"fixture-session\",\"uid\":1000}");
        accepted(&f, reordered, reference);
        sd_json_variant_unref(reordered);
        test_schema(&f, reference);
        test_context(&f, reference);
        test_evidence(&f, request, reference);
        test_tampered_records(&f, request, reference);
        test_lifecycle(argv[1], request, reference);
        fixture_done(&f);
        sd_json_variant_unref(request);
        sd_json_variant_unref(reference);
        printf("Accepted %u matching requests; rejected %u invalid requests.\n", accepted_requests, rejected_requests);
        return 0;
}
