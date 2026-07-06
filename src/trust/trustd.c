/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * platformd-trustd — the platform-authentication state authority.
 *
 * Binds boot evidence, the logind sessions, user identity, and authentication
 * events into read-only records served over the Varlink interface
 * io.platformd.Trust, and evaluates named policies over them (fresh-user-
 * verification, local-trusted-session, verified-boot). It authenticates nothing,
 * gates nothing, and holds no secret; it observes and reports. It also produces
 * TPM-based attestation of the boot and runtime state. See docs/platform-trust.md.
 */

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <systemd/sd-id128.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-json.h>
#include <systemd/sd-login.h>
#include <systemd/sd-varlink.h>

#include "attest.h"
#include "verify.h"

#define streq(a, b) (strcmp((a), (b)) == 0)
#define _cleanup_(f) __attribute__((cleanup(f)))
static inline void freep(void *p) { free(*(void **) p); }
#define _cleanup_free_ _cleanup_(freep)

/* A per-session lock + freshness overlay, updated by logind signals. Session
 * existence and the static attributes still come from sd-login on demand; this
 * only carries the state that must be observed over time. */
typedef struct TrackedSession {
        struct TrackedSession *next;
        char *id;
        char *path;               /* login1 session object path */
        bool locked;
        uint64_t last_verify;     /* CLOCK_MONOTONIC us of last unlock/creation; 0 = never */
} TrackedSession;

typedef struct AuthEvent {
        struct AuthEvent *next;
        char *user, *service, *tty, *rhost, *phase, *method, *result;
        uid_t uid;
        uint64_t when;            /* CLOCK_REALTIME us */
} AuthEvent;

typedef struct RuntimeEvent {
        struct RuntimeEvent *next;
        char *desc;
        char digest[65];          /* NV log value after this event (the running chain) */
        uint64_t when;            /* CLOCK_REALTIME us */
} RuntimeEvent;

typedef struct Manager {
        sd_event *event;
        sd_bus *bus;              /* system bus, for logind */
        sd_varlink_server *varlink;
        TrackedSession *sessions;
        AuthEvent *events;
        RuntimeEvent *runtime_log, *runtime_tail;
        unsigned n_events, n_runtime;
        char baseline_runtime[65];  /* NV log value before trustd's extensions this boot */
        uint64_t fresh_window;    /* seconds; the fresh-user-verification window */
} Manager;

static Manager *manager_instance;

static uint64_t now_mono(void) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
}

static uint64_t now_real(void) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        return (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
}

#define RUNTIME_LOG_MAX 1024

/* Fold a runtime auth/lock event into trustd's extend-only NV index and append it
 * to the measurement log. The NV value is later AK-certified, binding "user X
 * authenticated on this attested boot" to the TPM. */
static void record_runtime_event(Manager *m, const char *desc) {
        RuntimeEvent *e;
        uint8_t value[32];

        if (m->n_runtime >= RUNTIME_LOG_MAX)
                return;
        if (attest_nv_extend((const uint8_t *) desc, strlen(desc), value) < 0)
                return;   /* no TPM access — the event is simply not measured */
        if (!(e = calloc(1, sizeof *e)))
                return;
        e->desc = strdup(desc);
        for (int i = 0; i < 32; i++)
                snprintf(e->digest + 2 * i, 3, "%02x", value[i]);
        e->when = now_real();
        if (m->runtime_tail)
                m->runtime_tail->next = e;
        else
                m->runtime_log = e;
        m->runtime_tail = e;
        m->n_runtime++;
}

/* -1 when never verified, else whole seconds since the last verification. */
static int64_t seconds_since_verify(const TrackedSession *t) {
        if (!t || t->last_verify == 0)
                return -1;
        return (int64_t) ((now_mono() - t->last_verify) / 1000000);
}

/* --- boot evidence ----------------------------------------------------------- */

static char *read_os_release_field(const char *key) {
        FILE *f;
        char line[512];
        size_t klen = strlen(key);
        char *ret = NULL;

        f = fopen("/etc/os-release", "re");
        if (!f)
                f = fopen("/usr/lib/os-release", "re");
        if (!f)
                return NULL;

        while (fgets(line, sizeof line, f)) {
                char *v;
                size_t len;

                if (strncmp(line, key, klen) != 0 || line[klen] != '=')
                        continue;
                v = line + klen + 1;
                v[strcspn(v, "\n")] = 0;
                len = strlen(v);
                if (len >= 2 && (v[0] == '"' || v[0] == '\'') && v[len - 1] == v[0]) {
                        v[len - 1] = 0;
                        v++;
                }
                ret = strdup(v);
                break;
        }
        fclose(f);
        return ret;
}

/* The SecureBoot EFI variable is 4 attribute bytes then a 1-byte value. Readable
 * where the daemon has the privilege (as a system service it does); otherwise the
 * honest answer is "unknown", and "n/a" on non-UEFI firmware. */
static const char *read_secure_boot(void) {
        static const char *const var =
                "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
        uint8_t buf[5];
        ssize_t n;
        int fd;

        if (access("/sys/firmware/efi", F_OK) != 0)
                return "n/a";
        fd = open(var, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return "unknown";
        n = read(fd, buf, sizeof buf);
        close(fd);
        if (n < 5)
                return "unknown";
        return buf[4] ? "enabled" : "disabled";
}

static int vl_get_boot_evidence(sd_varlink *link, sd_json_variant *parameters,
                                sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *os_id = NULL, *os_name = NULL, *os_ver = NULL;
        char boots[SD_ID128_STRING_MAX] = "", machines[SD_ID128_STRING_MAX] = "";
        sd_id128_t id;
        int r;

        if (sd_id128_get_boot(&id) >= 0)
                sd_id128_to_string(id, boots);
        if (sd_id128_get_machine(&id) >= 0)
                sd_id128_to_string(id, machines);
        os_id = read_os_release_field("ID");
        os_name = read_os_release_field("PRETTY_NAME");
        os_ver = read_os_release_field("VERSION_ID");

        r = sd_json_buildo(&v,
                SD_JSON_BUILD_PAIR("bootId", SD_JSON_BUILD_STRING(boots)),
                SD_JSON_BUILD_PAIR("machineId", SD_JSON_BUILD_STRING(machines)),
                SD_JSON_BUILD_PAIR("osId", SD_JSON_BUILD_STRING(os_id ?: "")),
                SD_JSON_BUILD_PAIR("osName", SD_JSON_BUILD_STRING(os_name ?: "")),
                SD_JSON_BUILD_PAIR("osVersion", SD_JSON_BUILD_STRING(os_ver ?: "")),
                SD_JSON_BUILD_PAIR("firmware", SD_JSON_BUILD_STRING(access("/sys/firmware/efi", F_OK) == 0 ? "uefi" : "bios")),
                SD_JSON_BUILD_PAIR("secureBoot", SD_JSON_BUILD_STRING(read_secure_boot())),
                SD_JSON_BUILD_PAIR("tpmPresent", SD_JSON_BUILD_BOOLEAN(access("/sys/class/tpm/tpm0", F_OK) == 0)),
                SD_JSON_BUILD_PAIR("measuredBootAvailable", SD_JSON_BUILD_BOOLEAN(access("/sys/class/tpm/tpm0/pcr-sha256/0", R_OK) == 0)),
                SD_JSON_BUILD_PAIR("evidenceQuality", SD_JSON_BUILD_STRING("observed")));
        if (r < 0)
                return r;
        return sd_varlink_reply(link, v);
}

/* The measured boot: the TPM's SHA-256 PCR bank and whether the TCG event log is
 * available. Hardware-anchored — this is "measured", unlike the observed summary
 * above. The event log itself is forwarded to a verifier at attestation time. */
static const char *trust_state_dir(void) {
        const char *d = getenv("STATE_DIRECTORY");
        if (!d || !*d)
                d = getenv("PLATFORMD_TRUSTD_STATE");
        if (!d || !*d)
                d = "/var/lib/platformd-trustd";
        return d;
}

/* Does the live PCR 11 match a value in the provisioned boot reference? The
 * reference is written by `trustctl provision` (root-owned) on each UKI update. */
static bool boot_reference_matches(const char *live_pcr11) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ref = NULL;
        _cleanup_free_ char *path = NULL, *buf = NULL;
        sd_json_variant *arr;
        long sz;
        FILE *f;

        if (!*live_pcr11 || asprintf(&path, "%s/boot-reference.json", trust_state_dir()) < 0)
                return false;
        if (!(f = fopen(path, "re")))
                return false;
        if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) <= 0 || sz > 1048576) {
                fclose(f);
                return false;
        }
        rewind(f);
        if (!(buf = malloc((size_t) sz + 1)) || fread(buf, 1, (size_t) sz, f) != (size_t) sz) {
                fclose(f);
                return false;
        }
        fclose(f);
        buf[sz] = 0;
        if (sd_json_parse(buf, 0, &ref, NULL, NULL) < 0)
                return false;
        arr = sd_json_variant_by_key(ref, "pcr11");
        if (!arr || !sd_json_variant_is_array(arr))
                return false;
        for (size_t i = 0, n = sd_json_variant_elements(arr); i < n; i++) {
                sd_json_variant *e = sd_json_variant_by_index(arr, i);
                if (e && sd_json_variant_is_string(e) && strcasecmp(sd_json_variant_string(e), live_pcr11) == 0)
                        return true;
        }
        return false;
}

/* The running boot's quality: verified-local if the live PCR 11 matches the
 * provisioned reference, else measured (TPM present) or observed (no PCRs). */
static const char *current_boot_quality(void) {
        char hex[80];
        FILE *f = fopen("/sys/class/tpm/tpm0/pcr-sha256/11", "re");

        if (!f)
                return "observed";
        if (!fgets(hex, sizeof hex, f)) {
                fclose(f);
                return "observed";
        }
        fclose(f);
        hex[strcspn(hex, "\n")] = 0;
        return boot_reference_matches(hex) ? "verified-local" : "measured";
}

static int vl_get_measured_boot(sd_varlink *link, sd_json_variant *parameters,
                                sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *arr = NULL, *result = NULL;
        char pcr11[80] = "";
        bool available = false, evlog;
        const char *boot_quality;
        int r = 0;

        for (int i = 0; i < 24; i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *o = NULL;
                char path[64], hex[80];
                FILE *f;

                snprintf(path, sizeof path, "/sys/class/tpm/tpm0/pcr-sha256/%d", i);
                f = fopen(path, "re");
                if (!f)
                        continue;
                if (fgets(hex, sizeof hex, f)) {
                        hex[strcspn(hex, "\n")] = 0;
                        available = true;
                        if (i == 11)
                                strncpy(pcr11, hex, sizeof pcr11 - 1);
                        if (r == 0 &&
                            (r = sd_json_buildo(&o,
                                        SD_JSON_BUILD_PAIR("index", SD_JSON_BUILD_INTEGER(i)),
                                        SD_JSON_BUILD_PAIR("sha256", SD_JSON_BUILD_STRING(hex)))) >= 0)
                                r = sd_json_variant_append_array(&arr, o);
                }
                fclose(f);
        }
        if (r < 0)
                return r;
        if (!arr && (r = sd_json_variant_new_array(&arr, NULL, 0)) < 0)
                return r;

        /* verified-local: the running PCR 11 matches trustd's provisioned reference
         * for this UKI. measured: TPM present but no matching reference. */
        boot_quality = !available ? "observed" :
                       boot_reference_matches(pcr11) ? "verified-local" : "measured";

        evlog = access("/sys/kernel/security/tpm0/binary_bios_measurements", R_OK) == 0;
        r = sd_json_buildo(&result,
                SD_JSON_BUILD_PAIR("available", SD_JSON_BUILD_BOOLEAN(available)),
                SD_JSON_BUILD_PAIR("pcrBank", SD_JSON_BUILD_STRING(available ? "sha256" : "")),
                SD_JSON_BUILD_PAIR("pcrs", SD_JSON_BUILD_VARIANT(arr)),
                SD_JSON_BUILD_PAIR("eventLogPresent", SD_JSON_BUILD_BOOLEAN(evlog)),
                SD_JSON_BUILD_PAIR("bootQuality", SD_JSON_BUILD_STRING(boot_quality)),
                SD_JSON_BUILD_PAIR("evidenceQuality", SD_JSON_BUILD_STRING(available ? "measured" : "observed")));
        if (r < 0)
                return r;
        return sd_varlink_reply(link, result);
}

/* --- session tracking -------------------------------------------------------- */

static TrackedSession *find_tracked(Manager *m, const char *id) {
        for (TrackedSession *s = m->sessions; s; s = s->next)
                if (streq(s->id, id))
                        return s;
        return NULL;
}

static TrackedSession *find_tracked_by_path(Manager *m, const char *path) {
        for (TrackedSession *s = m->sessions; s; s = s->next)
                if (s->path && streq(s->path, path))
                        return s;
        return NULL;
}

/* `adopted` marks a session that already existed when the daemon started, versus
 * one we observed being created. A session's creation IS a successful
 * authentication, so a freshly-created unlocked session starts fresh; but for an
 * adopted session the last verification was never observed, so its honest record
 * is "never" — a daemon restart must not silently reset everyone's freshness. */
static void track_session(Manager *m, const char *id, const char *path, bool locked, bool adopted) {
        TrackedSession *s;

        if (find_tracked(m, id))
                return;
        if (!(s = calloc(1, sizeof *s)))
                return;
        s->id = strdup(id);
        s->path = path ? strdup(path) : NULL;
        if (!s->id) {
                free(s->path);
                free(s);
                return;
        }
        s->locked = locked;
        s->last_verify = (locked || adopted) ? 0 : now_mono();
        s->next = m->sessions;
        m->sessions = s;
}

static void untrack_by_path(Manager *m, const char *path) {
        for (TrackedSession **pp = &m->sessions; *pp; pp = &(*pp)->next)
                if ((*pp)->path && streq((*pp)->path, path)) {
                        TrackedSession *s = *pp;
                        *pp = s->next;
                        free(s->id);
                        free(s->path);
                        free(s);
                        return;
                }
}

/* --- verified identity via userdb -------------------------------------------- */

/* Query systemd-userdbd's homed-exclusive source for a uid's record. A signed
 * record means homed vouches for the identity with an Ed25519 key (verified);
 * otherwise it is an ordinary nss/passwd identity (declared). We read only the
 * public signing key and never expose the record's privileged section. */

static int userdb_query_identity(uid_t uid, bool *verified, char **source, char **signing_key) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        sd_json_variant *params, *record, *sig, *sig0, *key;
        struct sockaddr_un sa = { .sun_family = AF_UNIX };
        struct timeval tv = { .tv_sec = 2 };
        _cleanup_free_ char *buf = NULL;
        size_t buflen = 0, cap = 0;
        char req[256];
        int fd, len;

        *verified = false;
        *source = strdup("nss");
        *signing_key = strdup("");
        if (!*source || !*signing_key)
                return -ENOMEM;

        /* A raw Varlink exchange (JSON + NUL) on a fresh socket — NOT sd_varlink_call,
         * which re-enters the event loop and corrupts the heap inside a handler. */
        strncpy(sa.sun_path, "/run/systemd/userdb/io.systemd.Home", sizeof sa.sun_path - 1);
        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return 0;
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, (struct sockaddr *) &sa, sizeof sa) < 0) {
                close(fd);
                return 0;   /* homed not running — ordinary identity */
        }

        len = snprintf(req, sizeof req,
                "{\"method\":\"io.systemd.UserDatabase.GetUserRecord\","
                "\"parameters\":{\"uid\":%u,\"service\":\"io.systemd.Home\"}}",
                (unsigned) uid);
        if (len < 0 || len >= (int) sizeof req || write(fd, req, (size_t) len + 1) != (ssize_t) len + 1) {
                close(fd);
                return 0;
        }
        for (;;) {   /* read the reply up to its terminating NUL */
                char chunk[1024];
                ssize_t n = read(fd, chunk, sizeof chunk);
                char *nb;

                if (n <= 0)
                        break;
                if (buflen + (size_t) n + 1 > cap) {
                        cap = (buflen + (size_t) n + 1) * 2;
                        if (!(nb = realloc(buf, cap))) {
                                close(fd);
                                return 0;
                        }
                        buf = nb;
                }
                memcpy(buf + buflen, chunk, (size_t) n);
                buflen += (size_t) n;
                if (memchr(chunk, 0, (size_t) n))
                        break;
        }
        close(fd);
        if (!buf)
                return 0;
        buf[buflen] = 0;

        if (sd_json_parse(buf, 0, &reply, NULL, NULL) < 0 || sd_json_variant_by_key(reply, "error"))
                return 0;   /* no homed record for this uid — declared */
        params = sd_json_variant_by_key(reply, "parameters");
        record = params ? sd_json_variant_by_key(params, "record") : NULL;
        sig = record ? sd_json_variant_by_key(record, "signature") : NULL;
        sig0 = sig && sd_json_variant_is_array(sig) && sd_json_variant_elements(sig) > 0
                ? sd_json_variant_by_index(sig, 0) : NULL;
        if (sig0) {
                free(*source);
                *source = strdup("homed");
                key = sd_json_variant_by_key(sig0, "key");
                if (key && sd_json_variant_is_string(key)) {
                        free(*signing_key);
                        *signing_key = strdup(sd_json_variant_string(key));
                }
                *verified = user_record_verify(record);   /* verify the Ed25519 signature in-process */
        }
        return 0;
}

/* --- session records --------------------------------------------------------- */

static int session_to_json(Manager *m, const char *id, sd_json_variant **ret) {
        _cleanup_free_ char *seat = NULL, *type = NULL, *class = NULL, *state = NULL, *tty = NULL;
        TrackedSession *t = find_tracked(m, id);
        struct passwd *pw;
        uid_t uid = 0;
        pid_t leader = 0;
        int active, remote;

        (void) sd_session_get_uid(id, &uid);
        (void) sd_session_get_seat(id, &seat);
        (void) sd_session_get_type(id, &type);
        (void) sd_session_get_class(id, &class);
        (void) sd_session_get_state(id, &state);
        (void) sd_session_get_tty(id, &tty);
        (void) sd_session_get_leader(id, &leader);
        active = sd_session_is_active(id);
        remote = sd_session_is_remote(id);
        pw = getpwuid(uid);

        bool user_verified = false;
        _cleanup_free_ char *user_source = NULL, *signing_key = NULL;
        (void) userdb_query_identity(uid, &user_verified, &user_source, &signing_key);

        return sd_json_buildo(ret,
                SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_STRING(id)),
                SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(uid)),
                SD_JSON_BUILD_PAIR("user", SD_JSON_BUILD_STRING(pw && pw->pw_name ? pw->pw_name : "")),
                SD_JSON_BUILD_PAIR("seat", SD_JSON_BUILD_STRING(seat ?: "")),
                SD_JSON_BUILD_PAIR("type", SD_JSON_BUILD_STRING(type ?: "")),
                SD_JSON_BUILD_PAIR("class", SD_JSON_BUILD_STRING(class ?: "")),
                SD_JSON_BUILD_PAIR("state", SD_JSON_BUILD_STRING(state ?: "")),
                SD_JSON_BUILD_PAIR("active", SD_JSON_BUILD_BOOLEAN(active > 0)),
                SD_JSON_BUILD_PAIR("remote", SD_JSON_BUILD_BOOLEAN(remote > 0)),
                SD_JSON_BUILD_PAIR("locked", SD_JSON_BUILD_BOOLEAN(t && t->locked)),
                SD_JSON_BUILD_PAIR("secondsSinceVerification", SD_JSON_BUILD_INTEGER(seconds_since_verify(t))),
                SD_JSON_BUILD_PAIR("tty", SD_JSON_BUILD_STRING(tty ?: "")),
                SD_JSON_BUILD_PAIR("leader", SD_JSON_BUILD_UNSIGNED(leader)),
                SD_JSON_BUILD_PAIR("userVerified", SD_JSON_BUILD_BOOLEAN(user_verified)),
                SD_JSON_BUILD_PAIR("userSource", SD_JSON_BUILD_STRING(user_source ?: "")),
                SD_JSON_BUILD_PAIR("evidenceQuality", SD_JSON_BUILD_STRING("observed")));
}

static int vl_list_sessions(sd_varlink *link, sd_json_variant *parameters,
                            sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *arr = NULL, *result = NULL;
        char **ids = NULL;
        int n, r = 0;

        n = sd_get_sessions(&ids);
        if (n < 0)
                return n;
        for (int i = 0; i < n; i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *s = NULL;
                if (r == 0 && (r = session_to_json(manager_instance, ids[i], &s)) >= 0)
                        r = sd_json_variant_append_array(&arr, s);
        }
        for (int i = 0; i < n; i++)
                free(ids[i]);
        free(ids);
        if (r < 0)
                return r;

        if (!arr && (r = sd_json_variant_new_array(&arr, NULL, 0)) < 0)
                return r;
        r = sd_json_buildo(&result, SD_JSON_BUILD_PAIR("sessions", SD_JSON_BUILD_VARIANT(arr)));
        if (r < 0)
                return r;
        return sd_varlink_reply(link, result);
}

static int vl_get_session_trust(sd_varlink *link, sd_json_variant *parameters,
                                sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *s = NULL, *result = NULL;
        sd_json_variant *p;
        const char *sid = NULL;
        uid_t uid;
        int r;

        p = sd_json_variant_by_key(parameters, "sessionId");
        if (p && sd_json_variant_is_string(p))
                sid = sd_json_variant_string(p);
        if (!sid || !*sid)
                return sd_varlink_error_invalid_parameter_name(link, "sessionId");
        if (sd_session_get_uid(sid, &uid) < 0)
                return sd_varlink_error(link, "io.platformd.Trust.NoSuchSession", NULL);

        if ((r = session_to_json(manager_instance, sid, &s)) < 0)
                return r;
        r = sd_json_buildo(&result, SD_JSON_BUILD_PAIR("session", SD_JSON_BUILD_VARIANT(s)));
        if (r < 0)
                return r;
        return sd_varlink_reply(link, result);
}

/* Verified identity for a uid: the homed Ed25519 signing key (public), or a
 * declared nss identity. Evidence a verifier can appraise against a known key. */
static int vl_get_user_identity(sd_varlink *link, sd_json_variant *parameters,
                                sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        _cleanup_free_ char *source = NULL, *key = NULL;
        sd_json_variant *p;
        struct passwd *pw;
        uid_t uid;
        bool verified = false;
        int r;

        p = sd_json_variant_by_key(parameters, "uid");
        if (!p || !sd_json_variant_is_unsigned(p))
                return sd_varlink_error_invalid_parameter_name(link, "uid");
        uid = (uid_t) sd_json_variant_unsigned(p);

        (void) userdb_query_identity(uid, &verified, &source, &key);
        pw = getpwuid(uid);

        r = sd_json_buildo(&result,
                SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(pw && pw->pw_name ? pw->pw_name : "")),
                SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(uid)),
                SD_JSON_BUILD_PAIR("source", SD_JSON_BUILD_STRING(source ?: "")),
                SD_JSON_BUILD_PAIR("verified", SD_JSON_BUILD_BOOLEAN(verified)),
                SD_JSON_BUILD_PAIR("signingKey", SD_JSON_BUILD_STRING(key ?: "")),
                SD_JSON_BUILD_PAIR("identityQuality", SD_JSON_BUILD_STRING(verified ? "verified" : "declared")));
        if (r < 0)
                return r;
        return sd_varlink_reply(link, result);
}

/* --- policy ------------------------------------------------------------------ */

static int vl_evaluate_policy(sd_varlink *link, sd_json_variant *parameters,
                              sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = manager_instance;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *result = NULL;
        sd_json_variant *p;
        const char *policy = NULL, *sid = NULL, *reason = "";
        bool satisfied = false;
        uid_t uid;
        int r;

        p = sd_json_variant_by_key(parameters, "policy");
        if (p && sd_json_variant_is_string(p))
                policy = sd_json_variant_string(p);
        p = sd_json_variant_by_key(parameters, "sessionId");
        if (p && sd_json_variant_is_string(p))
                sid = sd_json_variant_string(p);

        if (!policy || !*policy)
                return sd_varlink_error_invalid_parameter_name(link, "policy");
        if (!streq(policy, "fresh-user-verification") && !streq(policy, "local-trusted-session") &&
            !streq(policy, "verified-boot"))
                return sd_varlink_error(link, "io.platformd.Trust.UnknownPolicy", NULL);

        if (streq(policy, "verified-boot")) {
                /* Boot integrity is a property of the platform, not a session: the
                 * boot reference either matches or it does not. Advisory — a
                 * compromised boot may misreport; the hard boundary is a TPM-bound
                 * credential, not this policy. */
                if (streq(current_boot_quality(), "verified-local")) {
                        satisfied = true;
                        reason = "boot matches the provisioned reference (verified-local)";
                } else
                        reason = "boot is not verified-local";
        } else if (!sid || sd_session_get_uid(sid, &uid) < 0)
                reason = "no such session";
        else {
                TrackedSession *t = find_tracked(m, sid);
                int64_t since = seconds_since_verify(t);
                bool fresh = false;

                /* Freshness — the base both policies require. */
                if (sd_session_is_active(sid) <= 0)
                        reason = "session is not active";
                else if (t && t->locked)
                        reason = "session is locked";
                else if (since < 0 || (uint64_t) since > m->fresh_window)
                        reason = "no fresh user verification";
                else
                        fresh = true;

                if (fresh && streq(policy, "fresh-user-verification")) {
                        satisfied = true;
                        reason = "session active and unlocked, verified within the window";
                } else if (fresh) {
                        /* local-trusted-session also needs a verified identity + boot. */
                        _cleanup_free_ char *usrc = NULL, *ukey = NULL;
                        const char *bq = current_boot_quality();
                        bool uverified = false;

                        (void) userdb_query_identity(uid, &uverified, &usrc, &ukey);
                        if (!uverified)
                                reason = "user identity is not verified (not a homed user)";
                        else if (!streq(bq, "verified-local"))
                                reason = "boot is only measured, not verified";
                        else {
                                satisfied = true;
                                reason = "verified identity on a verified-local boot, session fresh and unlocked";
                        }
                }
        }

        r = sd_json_buildo(&v,
                SD_JSON_BUILD_PAIR("policyId", SD_JSON_BUILD_STRING(policy)),
                SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(sid ?: "")),
                SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_STRING(satisfied ? "policy-satisfied" : "denied")),
                SD_JSON_BUILD_PAIR("reason", SD_JSON_BUILD_STRING(reason)),
                SD_JSON_BUILD_PAIR("windowSec", SD_JSON_BUILD_UNSIGNED(m->fresh_window)));
        if (r < 0)
                return r;
        r = sd_json_buildo(&result, SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_VARIANT(v)));
        if (r < 0)
                return r;
        return sd_varlink_reply(link, result);
}

/* --- logind tracking --------------------------------------------------------- */

static int on_lock(sd_bus_message *msg, void *userdata, sd_bus_error *e) {
        TrackedSession *t = find_tracked_by_path(userdata, sd_bus_message_get_path(msg));
        if (t) {
                char desc[128];
                t->locked = true;
                snprintf(desc, sizeof desc, "lock session=%s", t->id);
                record_runtime_event(userdata, desc);
        }
        return 0;
}

static int on_unlock(sd_bus_message *msg, void *userdata, sd_bus_error *e) {
        TrackedSession *t = find_tracked_by_path(userdata, sd_bus_message_get_path(msg));
        if (t) {
                char desc[128];
                t->locked = false;
                t->last_verify = now_mono();
                snprintf(desc, sizeof desc, "unlock session=%s", t->id);
                record_runtime_event(userdata, desc);
        }
        return 0;
}

/* PropertiesChanged(interface, changed a{sv}, invalidated as) — watch LockedHint. */
static int on_props(sd_bus_message *msg, void *userdata, sd_bus_error *e) {
        TrackedSession *t = find_tracked_by_path(userdata, sd_bus_message_get_path(msg));
        const char *iface;
        int locked = -1;

        if (!t || sd_bus_message_read(msg, "s", &iface) < 0 ||
            !streq(iface, "org.freedesktop.login1.Session"))
                return 0;
        if (sd_bus_message_enter_container(msg, 'a', "{sv}") < 0)
                return 0;
        while (sd_bus_message_enter_container(msg, 'e', "sv") > 0) {
                const char *key;
                if (sd_bus_message_read(msg, "s", &key) < 0)
                        break;
                if (streq(key, "LockedHint")) {
                        int v = 0;
                        if (sd_bus_message_enter_container(msg, 'v', "b") >= 0 &&
                            sd_bus_message_read(msg, "b", &v) >= 0) {
                                (void) sd_bus_message_exit_container(msg);
                                locked = v;
                        }
                } else
                        (void) sd_bus_message_skip(msg, "v");
                (void) sd_bus_message_exit_container(msg);
        }
        if (locked == 1)
                t->locked = true;
        else if (locked == 0) {
                t->locked = false;
                t->last_verify = now_mono();
        }
        return 0;
}

static int on_session_new(sd_bus_message *msg, void *userdata, sd_bus_error *e) {
        const char *id, *path;
        if (sd_bus_message_read(msg, "so", &id, &path) >= 0)
                track_session(userdata, id, path, false, false);   /* observed creation = fresh */
        return 0;
}

static int on_session_removed(sd_bus_message *msg, void *userdata, sd_bus_error *e) {
        const char *id, *path;
        if (sd_bus_message_read(msg, "so", &id, &path) >= 0)
                untrack_by_path(userdata, path);
        return 0;
}

/* Best-effort: without a system bus or logind, session state is simply absent. */
static void setup_logind(Manager *m) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        if (sd_bus_open_system(&m->bus) < 0 ||
            sd_bus_attach_event(m->bus, m->event, SD_EVENT_PRIORITY_NORMAL) < 0) {
                sd_journal_print(LOG_INFO, "no system bus — session lock/freshness unavailable");
                m->bus = sd_bus_flush_close_unref(m->bus);
                return;
        }

        r = sd_bus_call_method(m->bus, "org.freedesktop.login1", "/org/freedesktop/login1",
                               "org.freedesktop.login1.Manager", "ListSessions", NULL, &reply, "");
        if (r >= 0 && sd_bus_message_enter_container(reply, 'a', "(susso)") >= 0) {
                const char *id, *user, *seat, *path;
                uint32_t uid;
                int locked;

                while (sd_bus_message_read(reply, "(susso)", &id, &uid, &user, &seat, &path) > 0) {
                        locked = 0;
                        (void) sd_bus_get_property_trivial(m->bus, "org.freedesktop.login1", path,
                                        "org.freedesktop.login1.Session", "LockedHint", NULL, 'b', &locked);
                        track_session(m, id, path, locked > 0, true);   /* adopted: freshness unknown */
                }
                (void) sd_bus_message_exit_container(reply);
        }

        (void) sd_bus_match_signal(m->bus, NULL, "org.freedesktop.login1", NULL,
                        "org.freedesktop.login1.Session", "Lock", on_lock, m);
        (void) sd_bus_match_signal(m->bus, NULL, "org.freedesktop.login1", NULL,
                        "org.freedesktop.login1.Session", "Unlock", on_unlock, m);
        (void) sd_bus_match_signal(m->bus, NULL, "org.freedesktop.login1", NULL,
                        "org.freedesktop.DBus.Properties", "PropertiesChanged", on_props, m);
        (void) sd_bus_match_signal(m->bus, NULL, "org.freedesktop.login1", "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager", "SessionNew", on_session_new, m);
        (void) sd_bus_match_signal(m->bus, NULL, "org.freedesktop.login1", "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager", "SessionRemoved", on_session_removed, m);

        sd_journal_print(LOG_INFO, "tracking logind session lock state and freshness");
}

/* --- authentication events --------------------------------------------------- */

#define AUTH_EVENTS_MAX 64

static void auth_event_free(AuthEvent *e) {
        free(e->user); free(e->service); free(e->tty); free(e->rhost);
        free(e->phase); free(e->method); free(e->result);
        free(e);
}

static int auth_event_to_json(AuthEvent *e, sd_json_variant **ret) {
        return sd_json_buildo(ret,
                SD_JSON_BUILD_PAIR("user", SD_JSON_BUILD_STRING(e->user ?: "")),
                SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(e->uid)),
                SD_JSON_BUILD_PAIR("pamService", SD_JSON_BUILD_STRING(e->service ?: "")),
                SD_JSON_BUILD_PAIR("tty", SD_JSON_BUILD_STRING(e->tty ?: "")),
                SD_JSON_BUILD_PAIR("remoteHost", SD_JSON_BUILD_STRING(e->rhost ?: "")),
                SD_JSON_BUILD_PAIR("phase", SD_JSON_BUILD_STRING(e->phase ?: "")),
                SD_JSON_BUILD_PAIR("declaredMethod", SD_JSON_BUILD_STRING(e->method ?: "")),
                SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_STRING(e->result ?: "")),
                SD_JSON_BUILD_PAIR("realtimeUSec", SD_JSON_BUILD_UNSIGNED(e->when)),
                SD_JSON_BUILD_PAIR("evidenceQuality", SD_JSON_BUILD_STRING("declared")));
}

static char *json_dup_string(sd_json_variant *parameters, const char *key) {
        sd_json_variant *p = sd_json_variant_by_key(parameters, key);
        return p && sd_json_variant_is_string(p) ? strdup(sd_json_variant_string(p)) : NULL;
}

/* Only root may submit — the PAM module runs privileged, so this refuses forged
 * events from ordinary users on the world-readable socket. */
static int vl_submit_auth_event(sd_varlink *link, sd_json_variant *parameters,
                                sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = manager_instance;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *empty = NULL;
        sd_json_variant *p;
        AuthEvent *e;
        uid_t peer = (uid_t) -1;
        int r;

        if (sd_varlink_get_peer_uid(link, &peer) < 0 || peer != 0)
                return sd_varlink_error(link, "io.platformd.Trust.PermissionDenied", NULL);

        if (!(e = calloc(1, sizeof *e)))
                return -ENOMEM;
        e->when = now_real();
        e->user = json_dup_string(parameters, "user");
        e->service = json_dup_string(parameters, "pamService");
        e->tty = json_dup_string(parameters, "tty");
        e->rhost = json_dup_string(parameters, "remoteHost");
        e->phase = json_dup_string(parameters, "phase");
        e->method = json_dup_string(parameters, "declaredMethod");
        e->result = json_dup_string(parameters, "result");
        p = sd_json_variant_by_key(parameters, "uid");
        if (p && sd_json_variant_is_unsigned(p))
                e->uid = sd_json_variant_unsigned(p);

        e->next = m->events;
        m->events = e;
        if (++m->n_events > AUTH_EVENTS_MAX) {   /* drop the oldest */
                AuthEvent **pp = &m->events;
                while ((*pp)->next)
                        pp = &(*pp)->next;
                auth_event_free(*pp);
                *pp = NULL;
                m->n_events--;
        }

        /* a successful authentication is a fresh verification for its session */
        p = sd_json_variant_by_key(parameters, "sessionId");
        if (p && sd_json_variant_is_string(p) && e->result && streq(e->result, "success")) {
                TrackedSession *t = find_tracked(m, sd_json_variant_string(p));
                if (t) {
                        t->locked = false;
                        t->last_verify = now_mono();
                }
        }

        sd_journal_send("MESSAGE=platform-authentication event recorded",
                        "PLATFORMD_EVENT=auth-event",
                        "PLATFORMD_AUTH_USER=%s", e->user ?: "",
                        "PLATFORMD_AUTH_METHOD=%s", e->method ?: "",
                        "PLATFORMD_AUTH_RESULT=%s", e->result ?: "",
                        NULL);

        {       /* fold the event into the runtime NV log (AK-certified at attest) */
                char desc[256];
                snprintf(desc, sizeof desc, "auth user=%s method=%s result=%s",
                         e->user ?: "", e->method ?: "", e->result ?: "");
                record_runtime_event(m, desc);
        }

        if ((r = sd_json_variant_new_object(&empty, NULL, 0)) < 0)
                return r;
        return sd_varlink_reply(link, empty);
}

static int vl_list_auth_events(sd_varlink *link, sd_json_variant *parameters,
                               sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = manager_instance;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *arr = NULL, *result = NULL;
        int r = 0;

        for (AuthEvent *e = m->events; e && r >= 0; e = e->next) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *o = NULL;
                if ((r = auth_event_to_json(e, &o)) >= 0)
                        r = sd_json_variant_append_array(&arr, o);
        }
        if (r < 0)
                return r;
        if (!arr && (r = sd_json_variant_new_array(&arr, NULL, 0)) < 0)
                return r;
        r = sd_json_buildo(&result, SD_JSON_BUILD_PAIR("events", SD_JSON_BUILD_VARIANT(arr)));
        if (r < 0)
                return r;
        return sd_varlink_reply(link, result);
}

static int vl_get_runtime_log(sd_varlink *link, sd_json_variant *parameters,
                              sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = manager_instance;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *arr = NULL, *result = NULL;
        char current[65] = "";
        uint8_t nvval[32];
        int r = 0;

        for (RuntimeEvent *e = m->runtime_log; e && r >= 0; e = e->next) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *o = NULL;
                if ((r = sd_json_buildo(&o,
                                SD_JSON_BUILD_PAIR("description", SD_JSON_BUILD_STRING(e->desc ?: "")),
                                SD_JSON_BUILD_PAIR("digest", SD_JSON_BUILD_STRING(e->digest)),
                                SD_JSON_BUILD_PAIR("realtimeUSec", SD_JSON_BUILD_UNSIGNED(e->when)))) >= 0)
                        r = sd_json_variant_append_array(&arr, o);
        }
        if (r < 0)
                return r;
        if (!arr && (r = sd_json_variant_new_array(&arr, NULL, 0)) < 0)
                return r;
        if (attest_nv_read(nvval) == 0)
                for (int i = 0; i < 32; i++)
                        snprintf(current + 2 * i, 3, "%02x", nvval[i]);
        r = sd_json_buildo(&result,
                SD_JSON_BUILD_PAIR("nvIndex", SD_JSON_BUILD_STRING("0x01800001")),
                SD_JSON_BUILD_PAIR("baseline", SD_JSON_BUILD_STRING(m->baseline_runtime)),
                SD_JSON_BUILD_PAIR("current", SD_JSON_BUILD_STRING(current)),
                SD_JSON_BUILD_PAIR("events", SD_JSON_BUILD_VARIANT(arr)),
                SD_JSON_BUILD_PAIR("evidenceQuality", SD_JSON_BUILD_STRING(m->n_runtime > 0 ? "measured" : "observed")));
        if (r < 0)
                return r;
        return sd_varlink_reply(link, result);
}

/* --- attestation ------------------------------------------------------------- */

/* Producing evidence — a TPM quote, an NV certification, a credential activation
 * — is a signing operation on a shared, slow device; left open to every local
 * peer it would let any user monopolize the TPM and stall the daemon (and with
 * it every PAM gate check). Reading recorded state stays open to all; producing
 * fresh evidence is privileged. */
static bool peer_is_root(sd_varlink *link) {
        uid_t peer;
        return sd_varlink_get_peer_uid(link, &peer) >= 0 && peer == 0;
}

static char *hex_encode(const uint8_t *b, size_t n) {
        static const char digits[] = "0123456789abcdef";
        char *s = malloc(2 * n + 1);
        if (!s)
                return NULL;
        for (size_t i = 0; i < n; i++) {
                s[2 * i] = digits[b[i] >> 4];
                s[2 * i + 1] = digits[b[i] & 0x0f];
        }
        s[2 * n] = 0;
        return s;
}

static int hex_value(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
}

static int hex_decode(const char *hex, uint8_t **out, size_t *out_len) {
        size_t n = strlen(hex);
        uint8_t *p;

        if (n == 0 || n % 2)
                return -EINVAL;
        if (!(p = malloc(n / 2)))
                return -ENOMEM;
        for (size_t i = 0; i < n / 2; i++) {
                int hi = hex_value(hex[2 * i]), lo = hex_value(hex[2 * i + 1]);
                if (hi < 0 || lo < 0) {
                        free(p);
                        return -EINVAL;
                }
                p[i] = (uint8_t) (hi << 4 | lo);
        }
        *out = p;
        *out_len = n / 2;
        return 0;
}

/* The TCG event log (securityfs, root-readable) so a verifier can replay it to
 * the PCR values. Read to EOF — the log is often larger than one buffer, and a
 * truncated log cannot be replayed, so a short read returns NULL rather than
 * incomplete evidence. Returns a hex string (malloc'd), or NULL when unavailable. */
#define EVENT_LOG_MAX (4u * 1024 * 1024)

static char *read_event_log_hex(void) {
        _cleanup_free_ uint8_t *buf = NULL;
        size_t len = 0, cap = 0;
        FILE *f;

        f = fopen("/sys/kernel/security/tpm0/binary_bios_measurements", "re");
        if (!f)
                return NULL;
        for (;;) {
                size_t n;

                if (len == cap) {
                        uint8_t *nb = realloc(buf, cap += 65536);
                        if (!nb) {
                                fclose(f);
                                return NULL;
                        }
                        buf = nb;
                }
                n = fread(buf + len, 1, cap - len, f);
                len += n;
                if (n == 0) {   /* EOF or error — only a clean EOF is complete evidence */
                        bool complete = feof(f) != 0;
                        fclose(f);
                        return complete ? hex_encode(buf, len) : NULL;
                }
                if (len > EVENT_LOG_MAX) {
                        fclose(f);
                        return NULL;
                }
        }
}

static int vl_attest(sd_varlink *link, sd_json_variant *parameters,
                     sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        _cleanup_free_ uint8_t *nonce = NULL, *ak = NULL, *quoted = NULL, *sig = NULL;
        _cleanup_free_ char *ak_hex = NULL, *quoted_hex = NULL, *sig_hex = NULL, *evlog_hex = NULL;
        size_t nonce_len = 0, ak_len = 0, quoted_len = 0, sig_len = 0;
        sd_json_variant *p;
        int r;

        if (!peer_is_root(link))
                return sd_varlink_error(link, "io.platformd.Trust.PermissionDenied", NULL);

        p = sd_json_variant_by_key(parameters, "nonceHex");
        if (!p || !sd_json_variant_is_string(p) ||
            hex_decode(sd_json_variant_string(p), &nonce, &nonce_len) < 0 || nonce_len > 64)
                return sd_varlink_error_invalid_parameter_name(link, "nonceHex");

        r = attest_quote(nonce, nonce_len, &ak, &ak_len, &quoted, &quoted_len, &sig, &sig_len);
        if (r == -ENOTSUP)
                return sd_varlink_error(link, "io.platformd.Trust.AttestationUnsupported", NULL);
        if (r < 0)
                return sd_varlink_error(link, "io.platformd.Trust.AttestationFailed", NULL);

        ak_hex = hex_encode(ak, ak_len);
        quoted_hex = hex_encode(quoted, quoted_len);
        sig_hex = hex_encode(sig, sig_len);
        evlog_hex = read_event_log_hex();
        if (!ak_hex || !quoted_hex || !sig_hex)
                return -ENOMEM;

        r = sd_json_buildo(&result,
                SD_JSON_BUILD_PAIR("akPublicHex", SD_JSON_BUILD_STRING(ak_hex)),
                SD_JSON_BUILD_PAIR("quotedHex", SD_JSON_BUILD_STRING(quoted_hex)),
                SD_JSON_BUILD_PAIR("signatureHex", SD_JSON_BUILD_STRING(sig_hex)),
                SD_JSON_BUILD_PAIR("eventLogHex", SD_JSON_BUILD_STRING(evlog_hex ?: "")),
                SD_JSON_BUILD_PAIR("pcrBank", SD_JSON_BUILD_STRING("sha256")),
                SD_JSON_BUILD_PAIR("evidenceQuality", SD_JSON_BUILD_STRING("measured")));
        if (r < 0)
                return r;
        sd_journal_send("MESSAGE=attestation quote produced", "PLATFORMD_EVENT=attest", NULL);
        return sd_varlink_reply(link, result);
}

/* Assemble an IETF RATS Entity Attestation Token (RFC 9711, JSON profile): the
 * standard EAT claims plus the complete evidence as `measurements` — the AK-signed
 * TPM quote (the anchor), the boot PCRs + quality, and the runtime auth log. A
 * RATS Verifier consumes this directly: check the quote signature against cnf,
 * confirm the nonce, then replay the PCRs/runtime log against the quoted digest. */
static int vl_get_attestation_token(sd_varlink *link, sd_json_variant *parameters,
                                    sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = manager_instance;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *eat = NULL, *result = NULL,
                *pcrs = NULL, *revents = NULL, *measurements = NULL,
                *quote_m = NULL, *boot_m = NULL, *runtime_m = NULL, *cnf = NULL;
        _cleanup_free_ uint8_t *nonce = NULL, *ak = NULL, *quoted = NULL, *sig = NULL,
                *nv_ak = NULL, *nv_ci = NULL, *nv_sig = NULL;
        _cleanup_free_ char *ak_hex = NULL, *quoted_hex = NULL, *sig_hex = NULL, *eat_str = NULL,
                *nv_ci_hex = NULL, *nv_sig_hex = NULL;
        size_t nonce_len = 0, ak_len = 0, quoted_len = 0, sig_len = 0,
                nv_ak_len = 0, nv_ci_len = 0, nv_sig_len = 0;
        char machine_str[SD_ID128_STRING_MAX], nv_current[65] = "";
        uint8_t nvval[32];
        const char *nonce_hex, *sb;
        sd_id128_t machine;
        sd_json_variant *p;
        int r;

        if (!peer_is_root(link))
                return sd_varlink_error(link, "io.platformd.Trust.PermissionDenied", NULL);

        p = sd_json_variant_by_key(parameters, "nonceHex");
        if (!p || !sd_json_variant_is_string(p) ||
            hex_decode((nonce_hex = sd_json_variant_string(p)), &nonce, &nonce_len) < 0 || nonce_len > 64)
                return sd_varlink_error_invalid_parameter_name(link, "nonceHex");

        r = attest_quote(nonce, nonce_len, &ak, &ak_len, &quoted, &quoted_len, &sig, &sig_len);
        if (r == -ENOTSUP)
                return sd_varlink_error(link, "io.platformd.Trust.AttestationUnsupported", NULL);
        if (r < 0)
                return sd_varlink_error(link, "io.platformd.Trust.AttestationFailed", NULL);
        if (!(ak_hex = hex_encode(ak, ak_len)) ||
            !(quoted_hex = hex_encode(quoted, quoted_len)) ||
            !(sig_hex = hex_encode(sig, sig_len)))
                return -ENOMEM;

        /* AK-certify the runtime NV log (bound to the same nonce) and read it. */
        if (attest_nv_certify(nonce, nonce_len, &nv_ak, &nv_ak_len,
                              &nv_ci, &nv_ci_len, &nv_sig, &nv_sig_len) == 0) {
                nv_ci_hex = hex_encode(nv_ci, nv_ci_len);
                nv_sig_hex = hex_encode(nv_sig, nv_sig_len);
        }
        if (attest_nv_read(nvval) == 0)
                for (int i = 0; i < 32; i++)
                        snprintf(nv_current + 2 * i, 3, "%02x", nvval[i]);

        for (int i = 0; i <= 15; i++) {   /* boot PCRs the quote covers (runtime is in NV) */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *o = NULL;
                char path[64], hex[80];
                FILE *f;

                snprintf(path, sizeof path, "/sys/class/tpm/tpm0/pcr-sha256/%d", i);
                if (!(f = fopen(path, "re")))
                        continue;
                if (fgets(hex, sizeof hex, f)) {
                        hex[strcspn(hex, "\n")] = 0;
                        if (sd_json_buildo(&o, SD_JSON_BUILD_PAIR("index", SD_JSON_BUILD_INTEGER(i)),
                                              SD_JSON_BUILD_PAIR("sha256", SD_JSON_BUILD_STRING(hex))) >= 0)
                                sd_json_variant_append_array(&pcrs, o);
                }
                fclose(f);
        }
        if (!pcrs && (r = sd_json_variant_new_array(&pcrs, NULL, 0)) < 0)
                return r;

        for (RuntimeEvent *e = m->runtime_log; e; e = e->next) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *o = NULL;
                if (sd_json_buildo(&o,
                        SD_JSON_BUILD_PAIR("description", SD_JSON_BUILD_STRING(e->desc ?: "")),
                        SD_JSON_BUILD_PAIR("digest", SD_JSON_BUILD_STRING(e->digest)),
                        SD_JSON_BUILD_PAIR("realtimeUSec", SD_JSON_BUILD_UNSIGNED(e->when))) >= 0)
                        sd_json_variant_append_array(&revents, o);
        }
        if (!revents && (r = sd_json_variant_new_array(&revents, NULL, 0)) < 0)
                return r;

        if ((r = sd_json_buildo(&quote_m,
                        SD_JSON_BUILD_PAIR("type", SD_JSON_BUILD_STRING("tpm2-quote")),
                        SD_JSON_BUILD_PAIR("pcrBank", SD_JSON_BUILD_STRING("sha256")),
                        SD_JSON_BUILD_PAIR("quoted", SD_JSON_BUILD_STRING(quoted_hex)),
                        SD_JSON_BUILD_PAIR("signature", SD_JSON_BUILD_STRING(sig_hex)))) < 0 ||
            (r = sd_json_buildo(&boot_m,
                        SD_JSON_BUILD_PAIR("type", SD_JSON_BUILD_STRING("boot-pcrs")),
                        SD_JSON_BUILD_PAIR("quality", SD_JSON_BUILD_STRING(current_boot_quality())),
                        SD_JSON_BUILD_PAIR("pcrs", SD_JSON_BUILD_VARIANT(pcrs)))) < 0 ||
            (r = sd_json_buildo(&runtime_m,
                        SD_JSON_BUILD_PAIR("type", SD_JSON_BUILD_STRING("nv-runtime-log")),
                        SD_JSON_BUILD_PAIR("nvIndex", SD_JSON_BUILD_STRING("0x01800001")),
                        SD_JSON_BUILD_PAIR("baseline", SD_JSON_BUILD_STRING(m->baseline_runtime)),
                        SD_JSON_BUILD_PAIR("current", SD_JSON_BUILD_STRING(nv_current)),
                        SD_JSON_BUILD_PAIR("certifyInfo", SD_JSON_BUILD_STRING(nv_ci_hex ?: "")),
                        SD_JSON_BUILD_PAIR("signature", SD_JSON_BUILD_STRING(nv_sig_hex ?: "")),
                        SD_JSON_BUILD_PAIR("events", SD_JSON_BUILD_VARIANT(revents)))) < 0)
                return r;
        if ((r = sd_json_variant_append_array(&measurements, quote_m)) < 0 ||
            (r = sd_json_variant_append_array(&measurements, boot_m)) < 0 ||
            (r = sd_json_variant_append_array(&measurements, runtime_m)) < 0 ||
            (r = sd_json_buildo(&cnf, SD_JSON_BUILD_PAIR("tpm_ak", SD_JSON_BUILD_STRING(ak_hex)))) < 0)
                return r;

        sb = read_secure_boot();
        machine_str[0] = 0;
        if (sd_id128_get_machine(&machine) >= 0)
                sd_id128_to_string(machine, machine_str);

        r = sd_json_buildo(&eat,
                SD_JSON_BUILD_PAIR("eat_profile", SD_JSON_BUILD_STRING("https://platformd.io/trust/eat/v1")),
                SD_JSON_BUILD_PAIR("eat_nonce", SD_JSON_BUILD_STRING(nonce_hex)),
                SD_JSON_BUILD_PAIR("ueid", SD_JSON_BUILD_STRING(machine_str)),
                SD_JSON_BUILD_PAIR("iat", SD_JSON_BUILD_UNSIGNED(now_real() / 1000000)),
                SD_JSON_BUILD_PAIR("dbgstat", SD_JSON_BUILD_STRING(streq(sb, "enabled") ? "disabled" : "not-disabled")),
                SD_JSON_BUILD_PAIR("cnf", SD_JSON_BUILD_VARIANT(cnf)),
                SD_JSON_BUILD_PAIR("measurements", SD_JSON_BUILD_VARIANT(measurements)));
        if (r < 0)
                return r;
        if ((r = sd_json_variant_format(eat, SD_JSON_FORMAT_NEWLINE, &eat_str)) < 0)
                return r;

        r = sd_json_buildo(&result,
                SD_JSON_BUILD_PAIR("eat", SD_JSON_BUILD_STRING(eat_str)),
                SD_JSON_BUILD_PAIR("format", SD_JSON_BUILD_STRING("application/eat+json")),
                SD_JSON_BUILD_PAIR("evidenceQuality", SD_JSON_BUILD_STRING("measured")));
        if (r < 0)
                return r;
        sd_journal_send("MESSAGE=attestation token (EAT) produced", "PLATFORMD_EVENT=attest-eat", NULL);
        return sd_varlink_reply(link, result);
}

/* --- AK enrollment: bind the attestation key to a genuine TPM ----------------- */

static int vl_get_enrollment(sd_varlink *link, sd_json_variant *parameters,
                             sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        _cleanup_free_ uint8_t *ek = NULL, *ek_cert = NULL, *ak = NULL, *ak_name = NULL;
        _cleanup_free_ char *ek_hex = NULL, *ek_cert_hex = NULL, *ak_hex = NULL, *ak_name_hex = NULL;
        size_t ek_len = 0, ek_cert_len = 0, ak_len = 0, ak_name_len = 0;
        int r;

        if (!peer_is_root(link))
                return sd_varlink_error(link, "io.platformd.Trust.PermissionDenied", NULL);

        r = attest_get_enrollment(&ek, &ek_len, &ek_cert, &ek_cert_len,
                                  &ak, &ak_len, &ak_name, &ak_name_len);
        if (r == -ENOTSUP)
                return sd_varlink_error(link, "io.platformd.Trust.AttestationUnsupported", NULL);
        if (r < 0)
                return sd_varlink_error(link, "io.platformd.Trust.AttestationFailed", NULL);

        ek_hex = hex_encode(ek, ek_len);
        ak_hex = hex_encode(ak, ak_len);
        ak_name_hex = hex_encode(ak_name, ak_name_len);
        ek_cert_hex = ek_cert ? hex_encode(ek_cert, ek_cert_len) : NULL;
        if (!ek_hex || !ak_hex || !ak_name_hex)
                return -ENOMEM;

        r = sd_json_buildo(&result,
                SD_JSON_BUILD_PAIR("ekPublicHex", SD_JSON_BUILD_STRING(ek_hex)),
                SD_JSON_BUILD_PAIR("ekCertHex", SD_JSON_BUILD_STRING(ek_cert_hex ?: "")),
                SD_JSON_BUILD_PAIR("akPublicHex", SD_JSON_BUILD_STRING(ak_hex)),
                SD_JSON_BUILD_PAIR("akNameHex", SD_JSON_BUILD_STRING(ak_name_hex)),
                SD_JSON_BUILD_PAIR("evidenceQuality", SD_JSON_BUILD_STRING("measured")));
        if (r < 0)
                return r;
        return sd_varlink_reply(link, result);
}

static int vl_activate_credential(sd_varlink *link, sd_json_variant *parameters,
                                  sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        _cleanup_free_ uint8_t *cred = NULL, *secret = NULL, *challenge = NULL;
        _cleanup_free_ char *challenge_hex = NULL;
        size_t cred_len = 0, secret_len = 0, challenge_len = 0;
        sd_json_variant *pc, *ps;
        int r;

        if (!peer_is_root(link))
                return sd_varlink_error(link, "io.platformd.Trust.PermissionDenied", NULL);

        pc = sd_json_variant_by_key(parameters, "credentialHex");
        ps = sd_json_variant_by_key(parameters, "secretHex");
        if (!pc || !sd_json_variant_is_string(pc) ||
            hex_decode(sd_json_variant_string(pc), &cred, &cred_len) < 0)
                return sd_varlink_error_invalid_parameter_name(link, "credentialHex");
        if (!ps || !sd_json_variant_is_string(ps) ||
            hex_decode(sd_json_variant_string(ps), &secret, &secret_len) < 0)
                return sd_varlink_error_invalid_parameter_name(link, "secretHex");

        r = attest_activate_credential(cred, cred_len, secret, secret_len, &challenge, &challenge_len);
        if (r == -ENOTSUP)
                return sd_varlink_error(link, "io.platformd.Trust.AttestationUnsupported", NULL);
        if (r < 0)
                return sd_varlink_error(link, "io.platformd.Trust.AttestationFailed", NULL);

        if (!(challenge_hex = hex_encode(challenge, challenge_len)))
                return -ENOMEM;
        r = sd_json_buildo(&result,
                SD_JSON_BUILD_PAIR("challengeHex", SD_JSON_BUILD_STRING(challenge_hex)),
                SD_JSON_BUILD_PAIR("evidenceQuality", SD_JSON_BUILD_STRING("measured")));
        if (r < 0)
                return r;
        sd_journal_send("MESSAGE=credential activated (AK enrollment)", "PLATFORMD_EVENT=enroll", NULL);
        return sd_varlink_reply(link, result);
}

/* --- Varlink server ---------------------------------------------------------- */

static int setup_varlink(Manager *m) {
        _cleanup_free_ char *addr = NULL;
        const char *dir;
        int r;

        dir = getenv("RUNTIME_DIRECTORY");
        if (!dir || !*dir)
                dir = getenv("PLATFORMD_TRUSTD_RUNTIME");
        if (!dir || !*dir)
                dir = "/run/platformd-trustd";
        (void) mkdir(dir, 0755);
        if (asprintf(&addr, "%s/io.platformd.Trust", dir) < 0)
                return -ENOMEM;

        if ((r = sd_varlink_server_new(&m->varlink, 0)) < 0)
                return r;
        (void) sd_varlink_server_set_description(m->varlink, "platformd-trustd");
        if ((r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.GetBootEvidence", vl_get_boot_evidence)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.GetMeasuredBoot", vl_get_measured_boot)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.ListSessions", vl_list_sessions)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.GetSessionTrust", vl_get_session_trust)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.GetUserIdentity", vl_get_user_identity)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.EvaluatePolicy", vl_evaluate_policy)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.SubmitAuthEvent", vl_submit_auth_event)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.ListAuthEvents", vl_list_auth_events)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.GetRuntimeLog", vl_get_runtime_log)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.Attest", vl_attest)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.GetAttestationToken", vl_get_attestation_token)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.GetEnrollment", vl_get_enrollment)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.ActivateCredential", vl_activate_credential)) < 0)
                return r;
        (void) unlink(addr);
        if ((r = sd_varlink_server_listen_address(m->varlink, addr, 0666)) < 0 ||
            (r = sd_varlink_server_attach_event(m->varlink, m->event, SD_EVENT_PRIORITY_NORMAL)) < 0)
                return r;

        sd_journal_print(LOG_INFO, "Varlink: io.platformd.Trust on %s", addr);
        return 0;
}

int main(void) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        Manager manager = { .fresh_window = 300 };
        const char *fw;
        sigset_t ss;
        int r;

        if ((r = sd_event_default(&event)) < 0) {
                sd_journal_print(LOG_ERR, "sd_event_default: %s", strerror(-r));
                return EXIT_FAILURE;
        }
        manager.event = event;
        manager_instance = &manager;

        fw = getenv("PLATFORMD_TRUST_FRESH_WINDOW_SEC");
        if (fw && *fw)
                manager.fresh_window = strtoull(fw, NULL, 10);

        /* Record the NV log value before we extend it, so a verifier can replay
         * baseline + the runtime events up to the certified NV value. */
        {
                uint8_t value[32];
                if (attest_nv_read(value) == 0)
                        for (int i = 0; i < 32; i++)
                                snprintf(manager.baseline_runtime + 2 * i, 3, "%02x", value[i]);
        }

        sigemptyset(&ss);
        sigaddset(&ss, SIGTERM);
        sigaddset(&ss, SIGINT);
        sigprocmask(SIG_BLOCK, &ss, NULL);
        (void) sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
        (void) sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);

        setup_logind(&manager);   /* best-effort */
        if ((r = setup_varlink(&manager)) < 0) {
                sd_journal_print(LOG_ERR, "setup_varlink: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        sd_notify(false, "READY=1\n"
                         "STATUS=platformd-trustd: observing platform-authentication state");
        sd_journal_print(LOG_INFO, "platformd-trustd started (observability)");

        r = sd_event_loop(event);

        while (manager.sessions) {
                TrackedSession *s = manager.sessions;
                manager.sessions = s->next;
                free(s->id);
                free(s->path);
                free(s);
        }
        while (manager.events) {
                AuthEvent *e = manager.events;
                manager.events = e->next;
                auth_event_free(e);
        }
        while (manager.runtime_log) {
                RuntimeEvent *e = manager.runtime_log;
                manager.runtime_log = e->next;
                free(e->desc);
                free(e);
        }
        sd_bus_flush_close_unref(manager.bus);
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
