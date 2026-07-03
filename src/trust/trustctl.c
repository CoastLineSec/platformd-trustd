/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * trustctl — inspect and provision platformd-trustd's platform-authentication state.
 *
 * Mostly a read-only Varlink client of io.platformd.Trust (status, list-sessions,
 * session, explain, events, pcrs, attest). The `provision` verb is the exception:
 * run at UKI-install time by the kernel-install plugin, it records the expected
 * boot measurement so trustd can grade the running boot verified-local.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <systemd/sd-json.h>
#include <systemd/sd-login.h>
#include <systemd/sd-varlink.h>

#include "pe.h"

#define streq(a, b) (strcmp((a), (b)) == 0)
#define _cleanup_(f) __attribute__((cleanup(f)))
static inline void freep(void *p) { free(*(void **) p); }
#define _cleanup_free_ _cleanup_(freep)

static const char *jstr(sd_json_variant *v, const char *key) {
        sd_json_variant *m = v ? sd_json_variant_by_key(v, key) : NULL;
        return m && sd_json_variant_is_string(m) ? sd_json_variant_string(m) : "";
}

static int jbool(sd_json_variant *v, const char *key) {
        sd_json_variant *m = v ? sd_json_variant_by_key(v, key) : NULL;
        return m && sd_json_variant_is_boolean(m) && sd_json_variant_boolean(m);
}

static uint64_t juint(sd_json_variant *v, const char *key) {
        sd_json_variant *m = v ? sd_json_variant_by_key(v, key) : NULL;
        return m && sd_json_variant_is_unsigned(m) ? sd_json_variant_unsigned(m) : 0;
}

static int64_t jint(sd_json_variant *v, const char *key) {
        sd_json_variant *m = v ? sd_json_variant_by_key(v, key) : NULL;
        return m ? sd_json_variant_integer(m) : 0;
}

static sd_varlink *connect_trustd(void) {
        _cleanup_free_ char *addr = NULL;
        const char *dir = getenv("PLATFORMD_TRUSTD_RUNTIME");
        sd_varlink *link = NULL;

        if (!dir || !*dir)
                dir = "/run/platformd-trustd";
        if (asprintf(&addr, "%s/io.platformd.Trust", dir) < 0)
                return NULL;
        if (sd_varlink_connect_address(&link, addr) < 0) {
                fprintf(stderr, "trustctl: no platform-authentication authority is running (%s)\n", addr);
                return NULL;
        }
        return link;
}

static int call(sd_varlink *link, const char *method, sd_json_variant *params, sd_json_variant **ret) {
        const char *err = NULL;
        int r;

        r = sd_varlink_call(link, method, params, ret, &err);
        if (r < 0) {
                fprintf(stderr, "trustctl: call failed: %s\n", strerror(-r));
                return r;
        }
        if (err) {
                fprintf(stderr, "trustctl: %s\n", err);
                return -EIO;
        }
        return 0;
}

static void print_session(const char *id, sd_json_variant *s) {
        printf("Session %s:\n", id);
        printf("  user:      %s (uid %" PRIu64 ")\n", jstr(s, "user"), juint(s, "uid"));
        printf("  identity:  %s (%s)\n", jbool(s, "userVerified") ? "verified" : "declared", jstr(s, "userSource"));
        printf("  seat:      %-8s type=%s class=%s\n", jstr(s, "seat"), jstr(s, "type"), jstr(s, "class"));
        printf("  state:     %-8s active=%s remote=%s\n", jstr(s, "state"),
               jbool(s, "active") ? "yes" : "no", jbool(s, "remote") ? "yes" : "no");
        printf("  locked:    %s\n", jbool(s, "locked") ? "yes" : "no");
        if (jint(s, "secondsSinceVerification") < 0)
                printf("  verified:  no record\n");
        else
                printf("  verified:  %llds ago\n", (long long) jint(s, "secondsSinceVerification"));
        if (*jstr(s, "tty"))
                printf("  tty:       %s\n", jstr(s, "tty"));
        printf("  leader:    %" PRIu64 "\n", juint(s, "leader"));
        printf("  evidence:  %s\n", jstr(s, "evidenceQuality"));
}

static int cmd_status(void) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *boot = NULL, *sess = NULL, *params = NULL;
        _cleanup_free_ char *mysession = NULL;

        if (!(link = connect_trustd()))
                return EXIT_FAILURE;
        if (call(link, "io.platformd.Trust.GetBootEvidence", NULL, &boot) < 0)
                return EXIT_FAILURE;

        printf("Boot:\n");
        printf("  machine:   %s\n", jstr(boot, "machineId"));
        printf("  boot:      %s\n", jstr(boot, "bootId"));
        printf("  os:        %s\n", jstr(boot, "osName"));
        printf("  firmware:  %s   secure-boot=%s   tpm=%s\n", jstr(boot, "firmware"),
               jstr(boot, "secureBoot"), jbool(boot, "tpmPresent") ? "present" : "absent");
        printf("  measured:  boot PCRs %s\n", jbool(boot, "measuredBootAvailable") ? "available" : "unavailable");
        printf("  evidence:  %s\n", jstr(boot, "evidenceQuality"));

        if (sd_pid_get_session(0, &mysession) >= 0 &&
            sd_json_buildo(&params, SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(mysession))) >= 0 &&
            call(link, "io.platformd.Trust.GetSessionTrust", params, &sess) == 0) {
                printf("\n");
                print_session(mysession, sd_json_variant_by_key(sess, "session"));
        } else
                printf("\nSession:     none — this process is not in a logind session\n");
        return EXIT_SUCCESS;
}

static int cmd_list_sessions(void) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        sd_json_variant *arr;

        if (!(link = connect_trustd()))
                return EXIT_FAILURE;
        if (call(link, "io.platformd.Trust.ListSessions", NULL, &reply) < 0)
                return EXIT_FAILURE;

        printf("%-12s %-12s %-6s %-8s %-8s %s\n", "SESSION", "USER", "SEAT", "TYPE", "STATE", "ACTIVE");
        arr = sd_json_variant_by_key(reply, "sessions");
        for (size_t i = 0, n = arr ? sd_json_variant_elements(arr) : 0; i < n; i++) {
                sd_json_variant *s = sd_json_variant_by_index(arr, i);
                printf("%-12s %-12s %-6s %-8s %-8s %s\n",
                       jstr(s, "id"), jstr(s, "user"), jstr(s, "seat"), jstr(s, "type"),
                       jstr(s, "state"), jbool(s, "active") ? "yes" : "no");
        }
        return EXIT_SUCCESS;
}

static int cmd_session(const char *id) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *sess = NULL, *params = NULL;

        if (!(link = connect_trustd()))
                return EXIT_FAILURE;
        if (sd_json_buildo(&params, SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(id))) < 0)
                return EXIT_FAILURE;
        if (call(link, "io.platformd.Trust.GetSessionTrust", params, &sess) < 0)
                return EXIT_FAILURE;
        print_session(id, sd_json_variant_by_key(sess, "session"));
        return EXIT_SUCCESS;
}

static int cmd_explain(const char *policy, const char *session) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL, *params = NULL;
        sd_json_variant *r;

        if (!(link = connect_trustd()))
                return EXIT_FAILURE;
        if (sd_json_buildo(&params,
                        SD_JSON_BUILD_PAIR("policy", SD_JSON_BUILD_STRING(policy)),
                        SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(session))) < 0)
                return EXIT_FAILURE;
        if (call(link, "io.platformd.Trust.EvaluatePolicy", params, &reply) < 0)
                return EXIT_FAILURE;

        r = sd_json_variant_by_key(reply, "result");
        printf("policy:    %s\n", jstr(r, "policyId"));
        printf("session:   %s\n", jstr(r, "sessionId"));
        printf("result:    %s\n", jstr(r, "result"));
        printf("reason:    %s\n", jstr(r, "reason"));
        printf("window:    %" PRIu64 "s\n", juint(r, "windowSec"));
        /* exit 0 only when the policy is satisfied, so scripts can branch on it */
        return streq(jstr(r, "result"), "policy-satisfied") ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int cmd_events(void) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        sd_json_variant *arr;

        if (!(link = connect_trustd()))
                return EXIT_FAILURE;
        if (call(link, "io.platformd.Trust.ListAuthEvents", NULL, &reply) < 0)
                return EXIT_FAILURE;

        printf("%-20s %-12s %-14s %-9s %s\n", "WHEN", "USER", "SERVICE", "RESULT", "METHOD");
        arr = sd_json_variant_by_key(reply, "events");
        for (size_t i = 0, n = arr ? sd_json_variant_elements(arr) : 0; i < n; i++) {
                sd_json_variant *e = sd_json_variant_by_index(arr, i);
                uint64_t us = juint(e, "realtimeUSec");
                char when[24] = "-";

                if (us) {
                        time_t t = (time_t) (us / 1000000);
                        struct tm tm;
                        if (localtime_r(&t, &tm))
                                strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S", &tm);
                }
                printf("%-20s %-12s %-14s %-9s %s\n", when, jstr(e, "user"),
                       jstr(e, "pamService"), jstr(e, "result"), jstr(e, "declaredMethod"));
        }
        return EXIT_SUCCESS;
}

static int cmd_runtime_log(void) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        sd_json_variant *arr;
        size_t n;

        if (!(link = connect_trustd()))
                return EXIT_FAILURE;
        if (call(link, "io.platformd.Trust.GetRuntimeLog", NULL, &reply) < 0)
                return EXIT_FAILURE;

        printf("runtime auth log (extend-only NV %s)\n  baseline %s\n  current  %s\n",
               jstr(reply, "nvIndex"), jstr(reply, "baseline"), jstr(reply, "current"));
        arr = sd_json_variant_by_key(reply, "events");
        n = arr ? sd_json_variant_elements(arr) : 0;
        if (n == 0) {
                printf("  (no runtime events measured yet)\n");
                return EXIT_SUCCESS;
        }
        for (size_t i = 0; i < n; i++) {
                sd_json_variant *e = sd_json_variant_by_index(arr, i);
                uint64_t us = juint(e, "realtimeUSec");
                char when[16] = "-";

                if (us) {
                        time_t t = (time_t) (us / 1000000);
                        struct tm tm;
                        if (localtime_r(&t, &tm))
                                strftime(when, sizeof when, "%H:%M:%S", &tm);
                }
                printf("  %s  %-40s %.16s…\n", when, jstr(e, "description"), jstr(e, "digest"));
        }
        return EXIT_SUCCESS;
}

static int cmd_pcrs(void) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        sd_json_variant *arr;

        if (!(link = connect_trustd()))
                return EXIT_FAILURE;
        if (call(link, "io.platformd.Trust.GetMeasuredBoot", NULL, &reply) < 0)
                return EXIT_FAILURE;
        if (!jbool(reply, "available")) {
                printf("no TPM PCR bank available\n");
                return EXIT_SUCCESS;
        }
        printf("PCR bank: %s   event log: %s   boot: %s\n", jstr(reply, "pcrBank"),
               jbool(reply, "eventLogPresent") ? "present" : "absent", jstr(reply, "bootQuality"));
        arr = sd_json_variant_by_key(reply, "pcrs");
        for (size_t i = 0, n = arr ? sd_json_variant_elements(arr) : 0; i < n; i++) {
                sd_json_variant *p = sd_json_variant_by_index(arr, i);
                printf("  PCR %2lld  %s\n", (long long) jint(p, "index"), jstr(p, "sha256"));
        }
        return EXIT_SUCCESS;
}

static int cmd_attest(const char *nonce_arg) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL, *params = NULL;
        char generated[65];
        const char *nonce = nonce_arg, *ev;

        if (!nonce) {
                uint8_t rnd[32];
                FILE *f = fopen("/dev/urandom", "re");
                size_t n = f ? fread(rnd, 1, sizeof rnd, f) : 0;
                if (f)
                        fclose(f);
                if (n != sizeof rnd) {
                        fprintf(stderr, "trustctl: cannot generate a nonce\n");
                        return EXIT_FAILURE;
                }
                for (size_t i = 0; i < sizeof rnd; i++)
                        snprintf(generated + 2 * i, 3, "%02x", rnd[i]);
                nonce = generated;
                printf("nonce:     %s (generated)\n", nonce);
        }
        if (!(link = connect_trustd()))
                return EXIT_FAILURE;
        if (sd_json_buildo(&params, SD_JSON_BUILD_PAIR("nonceHex", SD_JSON_BUILD_STRING(nonce))) < 0)
                return EXIT_FAILURE;
        if (call(link, "io.platformd.Trust.Attest", params, &reply) < 0)
                return EXIT_FAILURE;

        printf("ak-public: %s\n", jstr(reply, "akPublicHex"));
        printf("quoted:    %s\n", jstr(reply, "quotedHex"));
        printf("signature: %s\n", jstr(reply, "signatureHex"));
        printf("pcr-bank:  %s   (%s)\n", jstr(reply, "pcrBank"), jstr(reply, "evidenceQuality"));
        ev = jstr(reply, "eventLogHex");
        printf("event-log: %s\n", *ev ? "included" : "unavailable");
        return EXIT_SUCCESS;
}

static int cmd_attest_token(const char *nonce_arg) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL, *params = NULL;
        char generated[65];
        const char *nonce = nonce_arg;

        if (!nonce) {
                uint8_t rnd[32];
                FILE *f = fopen("/dev/urandom", "re");
                size_t n = f ? fread(rnd, 1, sizeof rnd, f) : 0;
                if (f)
                        fclose(f);
                if (n != sizeof rnd) {
                        fprintf(stderr, "trustctl: cannot generate a nonce\n");
                        return EXIT_FAILURE;
                }
                for (size_t i = 0; i < sizeof rnd; i++)
                        snprintf(generated + 2 * i, 3, "%02x", rnd[i]);
                nonce = generated;
        }
        if (!(link = connect_trustd()))
                return EXIT_FAILURE;
        if (sd_json_buildo(&params, SD_JSON_BUILD_PAIR("nonceHex", SD_JSON_BUILD_STRING(nonce))) < 0)
                return EXIT_FAILURE;
        if (call(link, "io.platformd.Trust.GetAttestationToken", params, &reply) < 0)
                return EXIT_FAILURE;
        printf("%s\n", jstr(reply, "eat"));
        return EXIT_SUCCESS;
}

static int cmd_enroll(void) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        const char *cert;

        if (!(link = connect_trustd()))
                return EXIT_FAILURE;
        if (call(link, "io.platformd.Trust.GetEnrollment", NULL, &reply) < 0)
                return EXIT_FAILURE;
        printf("ek-public: %s\n", jstr(reply, "ekPublicHex"));
        cert = jstr(reply, "ekCertHex");
        printf("ek-cert  : %s\n", *cert ? cert : "(none in NV — firmware TPM)");
        printf("ak-public: %s\n", jstr(reply, "akPublicHex"));
        printf("ak-name  : %s\n", jstr(reply, "akNameHex"));
        return EXIT_SUCCESS;
}

static int cmd_activate_credential(const char *cred, const char *secret) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL, *params = NULL;

        if (!(link = connect_trustd()))
                return EXIT_FAILURE;
        if (sd_json_buildo(&params,
                        SD_JSON_BUILD_PAIR("credentialHex", SD_JSON_BUILD_STRING(cred)),
                        SD_JSON_BUILD_PAIR("secretHex", SD_JSON_BUILD_STRING(secret))) < 0)
                return EXIT_FAILURE;
        if (call(link, "io.platformd.Trust.ActivateCredential", params, &reply) < 0)
                return EXIT_FAILURE;
        printf("%s\n", jstr(reply, "challengeHex"));
        return EXIT_SUCCESS;
}

/* --- provision: record the boot reference (kernel-install path) -------------- */

static const char *state_dir(void) {
        const char *d = getenv("STATE_DIRECTORY");
        if (!d || !*d)
                d = getenv("PLATFORMD_TRUSTD_STATE");
        if (!d || !*d)
                d = "/var/lib/platformd-trustd";
        return d;
}

/* Run argv[] (no shell), capturing stdout into *out (malloc'd). Returns the exit
 * status, or -1 on a spawn failure. */
static int run_capture(char *const argv[], char **out) {
        _cleanup_free_ char *buf = NULL;
        size_t len = 0, cap = 0;
        int pipefd[2], status;
        pid_t pid;

        if (out)
                *out = NULL;
        if (pipe2(pipefd, O_CLOEXEC) < 0)
                return -1;
        if ((pid = fork()) < 0) {
                close(pipefd[0]);
                close(pipefd[1]);
                return -1;
        }
        if (pid == 0) {
                (void) dup2(pipefd[1], STDOUT_FILENO);
                close(pipefd[0]);
                close(pipefd[1]);
                execvp(argv[0], argv);
                _exit(127);
        }
        close(pipefd[1]);
        for (;;) {
                char chunk[4096];
                ssize_t n = read(pipefd[0], chunk, sizeof chunk);
                if (n <= 0)
                        break;
                if (out) {
                        char *nb;
                        if (len + (size_t) n + 1 > cap) {
                                cap = (len + (size_t) n + 1) * 2;
                                if (!(nb = realloc(buf, cap)))
                                        break;
                                buf = nb;
                        }
                        memcpy(buf + len, chunk, (size_t) n);
                        len += (size_t) n;
                }
        }
        close(pipefd[0]);
        if (waitpid(pid, &status, 0) < 0)
                return -1;
        if (out && buf) {
                buf[len] = 0;
                *out = buf;
                buf = NULL;
        }
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Parse the '11:sha256=<hex>' lines from systemd-measure output and write the
 * boot reference atomically (0600) to the state directory. */
static int write_boot_reference(const char *uki, const char *measure_out) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *arr = NULL, *ref = NULL;
        _cleanup_free_ char *formatted = NULL, *path = NULL, *tmp = NULL;
        const char *p = measure_out;
        int fd, nv = 0;

        while ((p = strstr(p, "11:sha256="))) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *s = NULL;
                char hex[80];
                size_t k = 0;

                p += strlen("11:sha256=");
                while (k < sizeof hex - 1 && isxdigit((unsigned char) p[k])) {
                        hex[k] = p[k];
                        k++;
                }
                hex[k] = 0;
                if (k == 0)
                        continue;
                if (sd_json_variant_new_string(&s, hex) < 0 || sd_json_variant_append_array(&arr, s) < 0)
                        return EXIT_FAILURE;
                nv++;
                p += k;
        }
        if (nv == 0) {
                fprintf(stderr, "trustctl: no PCR 11 prediction in systemd-measure output\n");
                return EXIT_FAILURE;
        }
        if (sd_json_buildo(&ref,
                        SD_JSON_BUILD_PAIR("pcrBank", SD_JSON_BUILD_STRING("sha256")),
                        SD_JSON_BUILD_PAIR("pcr11", SD_JSON_BUILD_VARIANT(arr)),
                        SD_JSON_BUILD_PAIR("uki", SD_JSON_BUILD_STRING(uki))) < 0 ||
            sd_json_variant_format(ref, SD_JSON_FORMAT_NEWLINE, &formatted) < 0)
                return EXIT_FAILURE;

        (void) mkdir(state_dir(), 0700);
        if (asprintf(&path, "%s/boot-reference.json", state_dir()) < 0 ||
            asprintf(&tmp, "%s/boot-reference.json.tmp", state_dir()) < 0)
                return EXIT_FAILURE;
        fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0 || write(fd, formatted, strlen(formatted)) != (ssize_t) strlen(formatted)) {
                if (fd >= 0)
                        close(fd);
                fprintf(stderr, "trustctl: cannot write %s: %s\n", tmp, strerror(errno));
                return EXIT_FAILURE;
        }
        close(fd);
        if (rename(tmp, path) < 0) {
                fprintf(stderr, "trustctl: cannot install %s: %s\n", path, strerror(errno));
                return EXIT_FAILURE;
        }
        printf("provisioned boot reference: %d PCR 11 value(s) for %s\n", nv, uki);
        return EXIT_SUCCESS;
}

static int cmd_provision(const char *uki) {
        static const char *const secs[] = {
                "linux", "osrel", "cmdline", "initrd", "uname", "sbat", "splash", "dtb", "ucode",
        };
        size_t nsec = sizeof secs / sizeof *secs;
        char tmpl[] = "/tmp/trustctl-provision.XXXXXX";
        char section_file[9][PATH_MAX];
        char measure_arg[9][PATH_MAX + 24];
        _cleanup_free_ char *out = NULL;
        char *margv[3 + 9 + 1];
        int mc = 0, rc = EXIT_FAILURE, fd;
        struct stat st;
        uint8_t *img;
        char *tmp;

        fd = open(uki, O_RDONLY | O_CLOEXEC);
        if (fd < 0 || fstat(fd, &st) < 0 || st.st_size <= 0) {
                fprintf(stderr, "trustctl: cannot read UKI %s: %s\n", uki, strerror(errno));
                if (fd >= 0)
                        close(fd);
                return EXIT_FAILURE;
        }
        img = mmap(NULL, (size_t) st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (img == MAP_FAILED) {
                fprintf(stderr, "trustctl: mmap %s: %s\n", uki, strerror(errno));
                return EXIT_FAILURE;
        }
        if (!(tmp = mkdtemp(tmpl))) {
                fprintf(stderr, "trustctl: mkdtemp: %s\n", strerror(errno));
                munmap(img, (size_t) st.st_size);
                return EXIT_FAILURE;
        }

        /* Extract each UKI PE section, then drive systemd-measure over the ones
         * present — the same computation systemd-stub does, reproducing PCR 11. */
        margv[mc++] = (char *) "/usr/lib/systemd/systemd-measure";
        margv[mc++] = (char *) "calculate";
        margv[mc++] = (char *) "--bank=sha256";
        for (size_t i = 0; i < nsec; i++) {
                char sect[16];

                snprintf(section_file[i], sizeof section_file[i], "%s/%s", tmp, secs[i]);
                snprintf(sect, sizeof sect, ".%s", secs[i]);
                if (pe_extract_section(img, (size_t) st.st_size, sect, section_file[i]) > 0) {
                        snprintf(measure_arg[i], sizeof measure_arg[i], "--%s=%s", secs[i], section_file[i]);
                        margv[mc++] = measure_arg[i];
                }
        }
        margv[mc] = NULL;
        munmap(img, (size_t) st.st_size);

        if (run_capture(margv, &out) != 0 || !out)
                fprintf(stderr, "trustctl: systemd-measure failed (is systemd-ukify installed?)\n");
        else
                rc = write_boot_reference(uki, out);

        for (size_t i = 0; i < nsec; i++)
                unlink(section_file[i]);
        (void) rmdir(tmp);
        return rc;
}

static void usage(void) {
        printf("trustctl — inspect platform-authentication state\n\n"
               "  trustctl status                   Boot evidence and this session\n"
               "  trustctl pcrs                     TPM PCR bank (measured boot)\n"
               "  trustctl attest [nonceHex]        Produce a TPM quote (attestation)\n"
               "  trustctl attest-token [nonceHex]  Full attestation as an IETF EAT token\n"
               "  trustctl enroll                   EK/AK enrollment evidence (credential activation)\n"
               "  trustctl activate-credential <cred> <secret>  Answer a MakeCredential challenge\n"
               "  trustctl list-sessions            All tracked logind sessions\n"
               "  trustctl session <id>             One session's trust record\n"
               "  trustctl explain <policy> [id]    Evaluate a named policy (id for session policies)\n"
               "  trustctl events                   Recent authentication events\n"
               "  trustctl runtime-log              Runtime auth measurement log (extend-only NV)\n"
               "  trustctl provision <uki>          Record the boot reference (kernel-install)\n");
}

int main(int argc, char *argv[]) {
        const char *cmd = argc > 1 ? argv[1] : "status";

        if (streq(cmd, "status"))
                return cmd_status();
        if (streq(cmd, "list-sessions"))
                return cmd_list_sessions();
        if (streq(cmd, "session") && argc > 2)
                return cmd_session(argv[2]);
        if (streq(cmd, "explain") && argc > 2)
                return cmd_explain(argv[2], argc > 3 ? argv[3] : "");
        if (streq(cmd, "events"))
                return cmd_events();
        if (streq(cmd, "runtime-log"))
                return cmd_runtime_log();
        if (streq(cmd, "provision") && argc > 2)
                return cmd_provision(argv[2]);
        if (streq(cmd, "pcrs"))
                return cmd_pcrs();
        if (streq(cmd, "attest"))
                return cmd_attest(argc > 2 ? argv[2] : NULL);
        if (streq(cmd, "attest-token"))
                return cmd_attest_token(argc > 2 ? argv[2] : NULL);
        if (streq(cmd, "enroll"))
                return cmd_enroll();
        if (streq(cmd, "activate-credential") && argc > 3)
                return cmd_activate_credential(argv[2], argv[3]);
        if (streq(cmd, "help") || streq(cmd, "-h") || streq(cmd, "--help")) {
                usage();
                return EXIT_SUCCESS;
        }
        fprintf(stderr, "trustctl: unknown or incomplete command '%s'\n\n", cmd);
        usage();
        return EXIT_FAILURE;
}
