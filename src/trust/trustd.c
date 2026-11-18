/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * platformd-trustd is the platform-authentication state authority.
 *
 * Binds boot evidence, the logind sessions, user identity, and authentication
 * events into read-only records served over the Varlink interface
 * io.platformd.Trust, and evaluates named policies over them (fresh-user-
 * verification, local-trusted-session, verified-boot). It authenticates nothing,
 * gates nothing, and holds no secret; it observes and reports. It also produces
 * TPM-based attestation of the boot and runtime state. See docs/platform-trust.md.
 */

#include <dirent.h>
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
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include "varlink-interface.h"

#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <systemd/sd-id128.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-json.h>
#include <systemd/sd-login.h>
#include <systemd/sd-varlink.h>

#include "attest.h"
#include "runtime-event.h"
#include "trust-util.h"
#include "verify.h"
#include "worker.h"

#define streq(a, b) (strcmp((a), (b)) == 0)
#define _cleanup_(f) __attribute__((cleanup(f)))
static inline void freep(void *p) { free(*(void **) p); }
#define _cleanup_free_ _cleanup_(freep)

typedef struct TrackedSession {
        struct TrackedSession *next;
        char *id;
        char *path;
        sd_bus_slot *lock_query;
        TrustSessionState state;
        uint64_t verification_invalidated_usec;
} TrackedSession;

typedef struct AuthEvent {
        struct AuthEvent *next;
        char *user, *service, *tty, *rhost, *phase, *method, *result, *session;
        uid_t uid;
        RuntimeTimestamp timestamp;
        bool qualifies_for_freshness;
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
        bool runtime_log_incomplete;
        char baseline_runtime[65];  /* NV log value before the retained window */
        uint64_t fresh_window;    /* seconds; the fresh-user-verification window */
        struct IdentityRequest *identity_requests;
        sd_json_variant *identities;
        sd_bus_slot *session_query;
        sd_event_source *session_retry;
        sd_event_source *reconnect;
        sd_bus_slot *sleep_query;
        sd_event_source *sleep_retry;
        int preparing_for_sleep;
        uint64_t session_generation, query_generation;
        uint64_t verification_invalidated_usec;
        struct BackendRequest *backend_head, *backend_tail;
        sd_json_variant *backend_result;
        int listener_lock;
} Manager;

static Manager *manager_instance;

static int identity_request(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_t method);
static void runtime_event_queue(Manager *m, const char *record, uint64_t realtime_usec);
static int backend_reply(sd_varlink *link, sd_json_variant *parameters);

static uint64_t now_boottime(void) {
        struct timespec ts;
        clock_gettime(CLOCK_BOOTTIME, &ts);
        return (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
}

static uint64_t now_real(void) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        return (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
}

#define RUNTIME_LOG_MAX 1024

static void record_runtime_event(Manager *m, const RuntimeTimestamp *timestamp, const char *type,
                                 const char *source, const char *quality, sd_json_variant *payload) {
        _cleanup_free_ char *record = NULL;
        RuntimeTimestamp current;

        if (!timestamp) {
                if (runtime_timestamp_now(&current) < 0) {
                        m->runtime_log_incomplete = true;
                        return;
                }
                timestamp = &current;
        }
        if (runtime_event_format(timestamp, type, source, quality, payload, &record) < 0) {
                m->runtime_log_incomplete = true;
                return;
        }
        runtime_event_queue(m, record, timestamp->realtime_usec);
}

static int64_t seconds_since_verify(const TrackedSession *t) {
        return trust_seconds_since_verification(t ? &t->state : NULL, now_boottime());
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
 * available. This is measured evidence, unlike the observed summary
 * above. The event log itself is forwarded to a verifier at attestation time. */
static const char *trust_state_dir(void) {
        const char *d = getenv("STATE_DIRECTORY");
        if (!d || !*d)
                d = getenv("PLATFORMD_TRUSTD_STATE");
        if (!d || !*d)
                d = "/var/lib/platformd-trustd";
        return d;
}

static bool boot_reference_file_matches(const char *path, const char *live_pcr11) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ref = NULL;
        _cleanup_free_ char *buf = NULL;
        sd_json_variant *arr;
        long sz;
        FILE *f;

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

/* Does the live PCR 11 match any root-provisioned UKI reference? Keep accepting
 * the original single-file location while installations migrate to the
 * per-entry boot-references directory. */
static bool boot_reference_matches(const char *live_pcr11) {
        _cleanup_free_ char *legacy = NULL, *dirpath = NULL;
        DIR *dir;

        if (!live_pcr11 || !*live_pcr11)
                return false;

        if (asprintf(&legacy, "%s/boot-reference.json", trust_state_dir()) >= 0 &&
            boot_reference_file_matches(legacy, live_pcr11))
                return true;

        if (asprintf(&dirpath, "%s/boot-references", trust_state_dir()) < 0)
                return false;
        if (!(dir = opendir(dirpath)))
                return false;

        for (;;) {
                _cleanup_free_ char *path = NULL;
                struct dirent *de;
                size_t l;

                errno = 0;
                if (!(de = readdir(dir)))
                        break;
                l = strlen(de->d_name);
                if (de->d_name[0] == '.' || l <= 5 || !streq(de->d_name + l - 5, ".json"))
                        continue;
                if (asprintf(&path, "%s/%s", dirpath, de->d_name) < 0)
                        continue;
                if (boot_reference_file_matches(path, live_pcr11)) {
                        closedir(dir);
                        return true;
                }
        }

        closedir(dir);
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

static int vl_get_measured_boot_run(sd_varlink *link, sd_json_variant *parameters,
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
                        if (i == 11) {
                                size_t n = strlen(hex);

                                memcpy(pcr11, hex, n + 1);
                        }
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
        return backend_reply(link, result);
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

static void invalidate_session_verification(TrackedSession *s) {
        RuntimeTimestamp timestamp;

        trust_session_invalidate_verification(&s->state);
        s->verification_invalidated_usec = runtime_timestamp_now(&timestamp) < 0
                ? UINT64_MAX : timestamp.boottime_usec;
}

static void invalidate_verification_epoch(Manager *m) {
        RuntimeTimestamp timestamp;

        m->verification_invalidated_usec = runtime_timestamp_now(&timestamp) < 0
                ? UINT64_MAX : timestamp.boottime_usec;
}

static int on_locked_hint(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        TrackedSession *s = userdata;
        int locked = -1;

        s->lock_query = sd_bus_slot_unref(s->lock_query);
        if (sd_bus_message_is_method_error(message, NULL) ||
            sd_bus_message_enter_container(message, 'v', "b") < 0 ||
            sd_bus_message_read(message, "b", &locked) <= 0)
                locked = -1;
        trust_session_set_lock(&s->state, locked);
        if (locked != 0)
                invalidate_session_verification(s);
        return 0;
}

static void query_locked_hint(Manager *m, TrackedSession *s) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *request = NULL;

        s->lock_query = sd_bus_slot_unref(s->lock_query);
        if (!m->bus || !s->path ||
            sd_bus_message_new_method_call(m->bus, &request, "org.freedesktop.login1", s->path,
                                           "org.freedesktop.DBus.Properties", "Get") < 0 ||
            sd_bus_message_append(request, "ss", "org.freedesktop.login1.Session", "LockedHint") < 0 ||
            sd_bus_call_async(m->bus, &s->lock_query, request, on_locked_hint, s, 2000000) < 0) {
                trust_session_set_lock(&s->state, -1);
                invalidate_session_verification(s);
        }
}

static void track_session(Manager *m, const char *id, const char *path, int locked) {
        TrackedSession *s = find_tracked(m, id);
        char *copy;

        if (!trust_text_valid(id, 256) || !*id || !path)
                return;
        if (s && s->path && streq(s->path, path))
                return;
        copy = strdup(path);
        if (!copy)
                return;
        if (!s) {
                s = calloc(1, sizeof *s);
                if (!s) {
                        free(copy);
                        return;
                }
                s->id = strdup(id);
                if (!s->id) {
                        free(copy);
                        free(s);
                        return;
                }
                s->next = m->sessions;
                m->sessions = s;
        }
        free(s->path);
        s->path = copy;
        trust_session_set_lock(&s->state, locked);
        trust_session_invalidate_verification(&s->state);
        query_locked_hint(m, s);
}

static void untrack_by_path(Manager *m, const char *path) {
        for (TrackedSession **pp = &m->sessions; *pp; pp = &(*pp)->next)
                if ((*pp)->path && streq((*pp)->path, path)) {
                        TrackedSession *s = *pp;
                        *pp = s->next;
                        sd_bus_slot_unref(s->lock_query);
                        free(s->id);
                        free(s->path);
                        free(s);
                        return;
                }
}

static TrackedSession *ensure_tracked_session(Manager *m, const char *id) {
        _cleanup_free_ char *path = NULL;
        TrackedSession *s = find_tracked(m, id);

        if (s)
                return s;
        if (sd_bus_path_encode("/org/freedesktop/login1/session", id, &path) < 0)
                return NULL;
        track_session(m, id, path, -1);
        return find_tracked(m, id);
}

/* --- verified identity via userdb -------------------------------------------- */

/* Query systemd-userdbd's homed-exclusive source for a uid's record. A signed
 * record means homed vouches for the identity with an Ed25519 key (verified);
 * otherwise it is an ordinary nss/passwd identity (declared). We read only the
 * public signing key and never expose the record's privileged section. */

static sd_json_variant *identity_find(uid_t uid) {
        sd_json_variant *records = manager_instance->identities;

        for (size_t i = 0; i < sd_json_variant_elements(records); i++) {
                sd_json_variant *record = sd_json_variant_by_index(records, i);
                sd_json_variant *id = sd_json_variant_by_key(record, "uid");

                if (sd_json_variant_is_unsigned(id) && sd_json_variant_unsigned(id) == uid)
                        return record;
        }
        return NULL;
}

static const char *identity_name(uid_t uid) {
        sd_json_variant *name = sd_json_variant_by_key(identity_find(uid), "userName");

        return sd_json_variant_is_string(name) ? sd_json_variant_string(name) : "";
}

static int userdb_query_identity(uid_t uid, bool *verified, char **source, char **signing_key) {
        sd_json_variant *record = identity_find(uid), *v;

        v = sd_json_variant_by_key(record, "verified");
        *verified = sd_json_variant_is_boolean(v) && sd_json_variant_boolean(v);
        v = sd_json_variant_by_key(record, "source");
        *source = strdup(sd_json_variant_is_string(v) ? sd_json_variant_string(v) : "nss");
        v = sd_json_variant_by_key(record, "signingKey");
        *signing_key = strdup(sd_json_variant_is_string(v) ? sd_json_variant_string(v) : "");
        return *source && *signing_key ? 0 : -ENOMEM;
}

typedef struct IdentityRequest {
        struct IdentityRequest *next;
        Worker *worker;
        sd_varlink *link;
        sd_json_variant *parameters;
        sd_varlink_method_t method;
        uid_t peer;
} IdentityRequest;

static int identity_read(uid_t uid, sd_json_variant **ret) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *request = NULL;
        _cleanup_free_ char *name = NULL;
        sd_json_variant *record, *record_uid, *record_name, *reply = NULL;
        const char *source = "nss", *key = NULL, *error = NULL;
        struct passwd *pw = getpwuid(uid);
        const char *address = "/run/systemd/userdb/io.systemd.Home";
        uid_t peer;

#ifdef TRUSTD_TESTING
        address = getenv("PLATFORMD_TRUST_TEST_USERDB") ?: "/nonexistent/platformd-test-userdb";
#endif
        name = strdup(pw && pw->pw_name ? pw->pw_name : "");
        if (!name)
                return -ENOMEM;
        if (sd_varlink_connect_address(&link, address) >= 0 &&
            sd_varlink_get_peer_uid(link, &peer) >= 0 && peer == 0 &&
            sd_varlink_set_relative_timeout(link, 2000000) >= 0 &&
            sd_json_buildo(&request, SD_JSON_BUILD_PAIR_UNSIGNED("uid", uid),
                          SD_JSON_BUILD_PAIR_STRING("service", "io.systemd.Home")) >= 0 &&
            sd_varlink_call(link, "io.systemd.UserDatabase.GetUserRecord", request, &reply, &error) >= 0 &&
            !error) {
                record = sd_json_variant_by_key(reply, "record");
                sd_json_variant_sensitive(record);
                record_uid = sd_json_variant_by_key(record, "uid");
                record_name = sd_json_variant_by_key(record, "userName");
                if (sd_json_variant_is_unsigned(record_uid) && sd_json_variant_unsigned(record_uid) == uid &&
                    sd_json_variant_is_string(record_name) &&
                    streq(sd_json_variant_string(record_name), name)) {
                        source = "homed";
                        key = user_record_signing_key(record);
                }
        }
        return sd_json_buildo(ret,
                             SD_JSON_BUILD_PAIR_UNSIGNED("uid", uid),
                             SD_JSON_BUILD_PAIR_STRING("userName", name),
                             SD_JSON_BUILD_PAIR_STRING("source", source),
                             SD_JSON_BUILD_PAIR_BOOLEAN("verified", key != NULL),
                             SD_JSON_BUILD_PAIR_STRING("signingKey", key ?: ""));
}

static int identity_run(void *userdata, sd_json_variant **ret) {
        IdentityRequest *q = userdata;
        sd_json_variant *p = sd_json_variant_by_key(q->parameters, "uid");
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *record = NULL;
        char **sessions = NULL;
        int n, r;

        if (sd_json_variant_by_key(q->parameters, "policy")) {
                r = sd_json_buildo(&record, SD_JSON_BUILD_PAIR_STRING("bootQuality", current_boot_quality()));
                if (r < 0 || (r = sd_json_variant_append_array(ret, record)) < 0)
                        return r;
                record = sd_json_variant_unref(record);
        }
        if (sd_json_variant_is_unsigned(p)) {
                r = identity_read((uid_t) sd_json_variant_unsigned(p), &record);
                return r < 0 ? r : sd_json_variant_append_array(ret, record);
        }
        p = sd_json_variant_by_key(q->parameters, "sessionId");
        if (sd_json_variant_is_string(p)) {
                uid_t uid;

                if (sd_session_get_uid(sd_json_variant_string(p), &uid) < 0)
                        return *ret ? 0 : sd_json_variant_new_array(ret, NULL, 0);
                r = identity_read(uid, &record);
                return r < 0 ? r : sd_json_variant_append_array(ret, record);
        }
        n = sd_get_sessions(&sessions);
        if (n < 0)
                return n;
        r = n > 256 ? -E2BIG : sd_json_variant_new_array(ret, NULL, 0);
        for (int i = 0; i < n; i++) {
                uid_t uid;

                if (r >= 0 && sd_session_get_uid(sessions[i], &uid) >= 0) {
                        record = sd_json_variant_unref(record);
                        r = identity_read(uid, &record);
                        if (r >= 0)
                                r = sd_json_variant_append_array(ret, record);
                }
                free(sessions[i]);
        }
        free(sessions);
        return r;
}

static void identity_free(IdentityRequest *q) {
        if (!q)
                return;
        worker_free(q->worker);
        sd_varlink_unref(q->link);
        sd_json_variant_unref(q->parameters);
        free(q);
}

static void identity_done(int error, sd_json_variant *result, void *userdata) {
        IdentityRequest *q = userdata;
        Manager *m = manager_instance;
        int r;

        for (IdentityRequest **p = &m->identity_requests; *p; p = &(*p)->next)
                if (*p == q) {
                        *p = q->next;
                        break;
                }
        if (error < 0)
                (void) sd_varlink_error_errno(q->link, error);
        else {
                m->identities = result;
                r = q->method(q->link, q->parameters, 0, m);
                m->identities = NULL;
                if (r < 0)
                        (void) sd_varlink_error_errno(q->link, r);
        }
        identity_free(q);
}

static int identity_request(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_t method) {
        Manager *m = manager_instance;
        IdentityRequest *q;
        uid_t peer;
        unsigned total = 0, owned = 0;
        int r;

        if (sd_varlink_get_peer_uid(link, &peer) < 0)
                return -EIO;
        for (q = m->identity_requests; q; q = q->next) {
                total++;
                owned += q->peer == peer;
        }
        if (total >= 16 || owned >= 4)
                return -EBUSY;
        q = calloc(1, sizeof *q);
        if (!q)
                return -ENOMEM;
        q->link = sd_varlink_ref(link);
        q->parameters = sd_json_variant_ref(parameters);
        q->method = method;
        q->peer = peer;
        r = worker_start(m->event, 2000000, identity_run, identity_done, q, &q->worker);
        if (r < 0) {
                identity_free(q);
                return r;
        }
        q->next = m->identity_requests;
        m->identity_requests = q;
        return 1;
}

/* --- session records --------------------------------------------------------- */

static int session_to_json(Manager *m, const char *id, sd_json_variant **ret) {
        _cleanup_free_ char *seat = NULL, *type = NULL, *class = NULL, *state = NULL, *tty = NULL;
        TrackedSession *t = find_tracked(m, id);
        const char *lock_state, *verification_quality, *verification_source;
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

        bool user_verified = false;
        _cleanup_free_ char *user_source = NULL, *signing_key = NULL;
        (void) userdb_query_identity(uid, &user_verified, &user_source, &signing_key);

        lock_state = !t || t->state.lock_state < 0 ? "unknown" :
                     t->state.lock_state > 0 ? "locked" : "unlocked";
        verification_source = t && t->state.last_verification_boottime_usec > 0
                ? "platformd-verifyd"
                : "";
        verification_quality = *verification_source ? "declared" : "unavailable";

        return sd_json_buildo(ret,
                SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_STRING(id)),
                SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(uid)),
                SD_JSON_BUILD_PAIR("user", SD_JSON_BUILD_STRING(identity_name(uid))),
                SD_JSON_BUILD_PAIR("seat", SD_JSON_BUILD_STRING(seat ?: "")),
                SD_JSON_BUILD_PAIR("type", SD_JSON_BUILD_STRING(type ?: "")),
                SD_JSON_BUILD_PAIR("class", SD_JSON_BUILD_STRING(class ?: "")),
                SD_JSON_BUILD_PAIR("state", SD_JSON_BUILD_STRING(state ?: "")),
                SD_JSON_BUILD_PAIR("active", SD_JSON_BUILD_BOOLEAN(active > 0)),
                SD_JSON_BUILD_PAIR("remote", SD_JSON_BUILD_BOOLEAN(remote > 0)),
                SD_JSON_BUILD_PAIR("locked", SD_JSON_BUILD_BOOLEAN(
                                t && t->state.lock_state > 0)),
                SD_JSON_BUILD_PAIR("lockState", SD_JSON_BUILD_STRING(lock_state)),
                SD_JSON_BUILD_PAIR("secondsSinceVerification", SD_JSON_BUILD_INTEGER(seconds_since_verify(t))),
                SD_JSON_BUILD_PAIR("verificationRealtimeUSec", SD_JSON_BUILD_UNSIGNED(
                                t ? t->state.last_verification_realtime_usec : 0)),
                SD_JSON_BUILD_PAIR("verificationSource", SD_JSON_BUILD_STRING(verification_source)),
                SD_JSON_BUILD_PAIR("verificationQuality", SD_JSON_BUILD_STRING(verification_quality)),
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

        if (!manager_instance->identities)
                return identity_request(link, parameters, vl_list_sessions);
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

        if (!manager_instance->identities)
                return identity_request(link, parameters, vl_get_session_trust);
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
        uid_t uid;
        bool verified = false;
        int r;

        p = sd_json_variant_by_key(parameters, "uid");
        if (!p || !sd_json_variant_is_unsigned(p) || sd_json_variant_unsigned(p) >= (uid_t) -1)
                return sd_varlink_error_invalid_parameter_name(link, "uid");
        uid = (uid_t) sd_json_variant_unsigned(p);

        if (!manager_instance->identities)
                return identity_request(link, parameters, vl_get_user_identity);
        (void) userdb_query_identity(uid, &verified, &source, &key);

        r = sd_json_buildo(&result,
                SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(identity_name(uid))),
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
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *record = NULL, *result = NULL;
        _cleanup_free_ char *class = NULL, *source = NULL, *key = NULL;
        TrustPolicyInput input = {
                .active = -1,
                .class_eligible = -1,
                .lock_state = -1,
                .remote = -1,
                .seconds_since_verification = -1,
                .freshness_window_sec = m->fresh_window,
        };
        TrustPolicyDecision decision;
        sd_json_variant *p;
        const char *policy, *sid;
        uid_t uid = 0;
        int r;

        p = sd_json_variant_by_key(parameters, "policy");
        if (!p || !sd_json_variant_is_string(p))
                return sd_varlink_error_invalid_parameter_name(link, "policy");
        policy = sd_json_variant_string(p);
        if (!trust_text_valid(policy, 64) || !*policy)
                return sd_varlink_error_invalid_parameter_name(link, "policy");

        p = sd_json_variant_by_key(parameters, "sessionId");
        if (!p || !sd_json_variant_is_string(p))
                return sd_varlink_error_invalid_parameter_name(link, "sessionId");
        sid = sd_json_variant_string(p);
        if (!trust_text_valid(sid, 256))
                return sd_varlink_error_invalid_parameter_name(link, "sessionId");

        if (!streq(policy, "fresh-user-verification") && !streq(policy, "local-trusted-session") &&
            !streq(policy, "verified-boot"))
                return sd_varlink_error(link, "io.platformd.Trust.UnknownPolicy", NULL);
        if (!streq(policy, "fresh-user-verification") && !m->identities)
                return identity_request(link, parameters, vl_evaluate_policy);
        if (!streq(policy, "fresh-user-verification")) {
                sd_json_variant *quality = sd_json_variant_by_key(
                                sd_json_variant_by_index(m->identities, 0), "bootQuality");
                input.boot_verified = sd_json_variant_is_string(quality) &&
                                      streq(sd_json_variant_string(quality), "verified-local");
        }
        if (*sid && sd_session_get_uid(sid, &uid) >= 0) {
                TrackedSession *tracked = find_tracked(m, sid);

                input.session_exists = true;
                input.active = sd_session_is_active(sid);
                input.remote = sd_session_is_remote(sid);
                if (sd_session_get_class(sid, &class) >= 0)
                        input.class_eligible = trust_session_class_allowed(class);
                if (tracked) {
                        input.lock_state = tracked->state.lock_state;
                        input.seconds_since_verification = seconds_since_verify(tracked);
                }
                if (streq(policy, "local-trusted-session"))
                        (void) userdb_query_identity(uid, &input.user_verified, &source, &key);
        }

        r = trust_evaluate_policy(policy, &input, &decision);
        if (r == -EOPNOTSUPP)
                return sd_varlink_error(link, "io.platformd.Trust.UnknownPolicy", NULL);
        if (r < 0)
                return r;

        r = sd_json_buildo(&record,
                SD_JSON_BUILD_PAIR("policyId", SD_JSON_BUILD_STRING(policy)),
                SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(sid)),
                SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_STRING(
                                decision.satisfied ? "policy-satisfied" : "denied")),
                SD_JSON_BUILD_PAIR("reasonCode", SD_JSON_BUILD_STRING(decision.reason_code)),
                SD_JSON_BUILD_PAIR("reason", SD_JSON_BUILD_STRING(decision.reason)),
                SD_JSON_BUILD_PAIR("windowSec", SD_JSON_BUILD_UNSIGNED(m->fresh_window)));
        if (r < 0)
                return r;
        r = sd_json_buildo(
                        &result,
                        SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_VARIANT(record)));
        if (r < 0)
                return r;
        return sd_varlink_reply(link, result);
}

/* --- logind tracking --------------------------------------------------------- */

static void setup_logind(Manager *m);
static void enumerate_sessions(Manager *m);
static void query_preparing_for_sleep(Manager *m);

static void set_preparing_for_sleep(Manager *m, int preparing) {
        m->preparing_for_sleep = preparing;
        invalidate_verification_epoch(m);
        for (TrackedSession *s = m->sessions; s; s = s->next)
                invalidate_session_verification(s);
}

static void forget_sleep_state(Manager *m) {
        m->sleep_query = sd_bus_slot_unref(m->sleep_query);
        m->sleep_retry = sd_event_source_unref(m->sleep_retry);
        set_preparing_for_sleep(m, -1);
}

static int on_sleep_retry(sd_event_source *source, uint64_t usec, void *userdata) {
        Manager *m = userdata;

        m->sleep_retry = sd_event_source_unref(m->sleep_retry);
        query_preparing_for_sleep(m);
        return 0;
}

static void schedule_sleep_retry(Manager *m) {
        if (!m->sleep_retry)
                (void) sd_event_add_time(m->event, &m->sleep_retry, CLOCK_BOOTTIME,
                                        now_boottime() + 2000000, 0, on_sleep_retry, m);
}

static int on_preparing_for_sleep(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int preparing = -1;

        m->sleep_query = sd_bus_slot_unref(m->sleep_query);
        if (sd_bus_message_is_method_error(message, NULL) ||
            sd_bus_message_enter_container(message, 'v', "b") <= 0 ||
            sd_bus_message_read(message, "b", &preparing) <= 0 ||
            sd_bus_message_exit_container(message) < 0 ||
            sd_bus_message_at_end(message, true) <= 0)
                preparing = -1;
        set_preparing_for_sleep(m, preparing);
        if (preparing < 0)
                schedule_sleep_retry(m);
        return 0;
}

static void query_preparing_for_sleep(Manager *m) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *request = NULL;

        forget_sleep_state(m);
        if (!m->bus ||
            sd_bus_message_new_method_call(m->bus, &request, "org.freedesktop.login1", "/org/freedesktop/login1",
                                           "org.freedesktop.DBus.Properties", "Get") < 0 ||
            sd_bus_message_append(request, "ss", "org.freedesktop.login1.Manager", "PreparingForSleep") < 0 ||
            sd_bus_call_async(m->bus, &m->sleep_query, request, on_preparing_for_sleep, m, 2000000) < 0)
                schedule_sleep_retry(m);
}

static void forget_sessions(Manager *m) {
        invalidate_verification_epoch(m);
        m->session_query = sd_bus_slot_unref(m->session_query);
        m->session_retry = sd_event_source_unref(m->session_retry);
        while (m->sessions)
                untrack_by_path(m, m->sessions->path);
}

static int on_session_retry(sd_event_source *source, uint64_t usec, void *userdata) {
        Manager *m = userdata;

        m->session_retry = sd_event_source_unref(m->session_retry);
        enumerate_sessions(m);
        return 0;
}

static void schedule_session_retry(Manager *m) {
        if (!m->session_retry)
                (void) sd_event_add_time(m->event, &m->session_retry, CLOCK_BOOTTIME,
                                        now_boottime() + 2000000, 0, on_session_retry, m);
}

static int on_props(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        TrackedSession *s = find_tracked_by_path(m, sd_bus_message_get_path(msg));
        const char *interface, *key;
        bool changed = false;
        int locked = -1, r;

        if (!s || sd_bus_message_read(msg, "s", &interface) <= 0 ||
            !streq(interface, "org.freedesktop.login1.Session"))
                return 0;
        if (sd_bus_message_enter_container(msg, 'a', "{sv}") <= 0)
                goto invalid;
        while ((r = sd_bus_message_enter_container(msg, 'e', "sv")) > 0) {
                if (sd_bus_message_read(msg, "s", &key) <= 0)
                        goto invalid;
                if (streq(key, "LockedHint")) {
                        if (changed || sd_bus_message_enter_container(msg, 'v', "b") <= 0 ||
                            sd_bus_message_read(msg, "b", &locked) <= 0 ||
                            sd_bus_message_exit_container(msg) < 0)
                                goto invalid;
                        changed = true;
                } else if (sd_bus_message_skip(msg, "v") < 0)
                        goto invalid;
                if (sd_bus_message_exit_container(msg) < 0)
                        goto invalid;
        }
        if (r < 0 || sd_bus_message_exit_container(msg) < 0 ||
            sd_bus_message_enter_container(msg, 'a', "s") <= 0)
                goto invalid;
        while ((r = sd_bus_message_read(msg, "s", &key)) > 0)
                if (streq(key, "LockedHint"))
                        goto invalid;
        if (r < 0)
                goto invalid;
        if (!changed)
                return 0;
        goto update;
invalid:
        locked = -1;
update:
        s->lock_query = sd_bus_slot_unref(s->lock_query);
        trust_session_set_lock(&s->state, locked);
        if (locked != 0)
                invalidate_session_verification(s);
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *payload = NULL;

                if (sd_json_buildo(&payload,
                                  SD_JSON_BUILD_PAIR_STRING("sessionId", s->id),
                                  SD_JSON_BUILD_PAIR_STRING("lockState", locked < 0 ? "unknown" : locked ? "locked" : "unlocked"),
                                  SD_JSON_BUILD_PAIR_BOOLEAN("freshnessInvalidated", locked != 0)) < 0)
                        m->runtime_log_incomplete = true;
                else
                        record_runtime_event(m, NULL, "lock-state", "org.freedesktop.login1.Session.LockedHint",
                                             "observed", payload);
        }
        return 0;
}

static int on_session_new(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *id, *path;

        m->session_generation++;
        if (sd_bus_message_read(msg, "so", &id, &path) > 0)
                track_session(m, id, path, -1);
        return 0;
}

static int on_session_removed(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *id, *path;

        m->session_generation++;
        if (sd_bus_message_read(msg, "so", &id, &path) > 0)
                untrack_by_path(m, path);
        return 0;
}

static int on_prepare_for_sleep(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *payload = NULL;
        int preparing = -1;

        forget_sleep_state(m);
        if (sd_bus_message_read(msg, "b", &preparing) <= 0 ||
            sd_bus_message_at_end(msg, true) <= 0)
                preparing = -1;
        set_preparing_for_sleep(m, preparing);
        if (preparing < 0)
                schedule_sleep_retry(m);
        if (sd_json_buildo(&payload,
                          SD_JSON_BUILD_PAIR_STRING("preparationState", preparing < 0 ? "unknown" : preparing ? "preparing" : "finished"),
                          SD_JSON_BUILD_PAIR_BOOLEAN("freshnessInvalidated", true)) < 0)
                m->runtime_log_incomplete = true;
        else
                record_runtime_event(m, NULL, "sleep-state", "org.freedesktop.login1.Manager.PrepareForSleep",
                                     "observed", payload);
        return 0;
}

static int on_sessions(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *id, *user, *seat, *path;
        uint32_t uid;
        int r;

        m->session_query = sd_bus_slot_unref(m->session_query);
        if (m->query_generation != m->session_generation) {
                schedule_session_retry(m);
                return 0;
        }
        if (sd_bus_message_is_method_error(msg, NULL) ||
            sd_bus_message_enter_container(msg, 'a', "(susso)") <= 0)
                goto fail;
        while ((r = sd_bus_message_read(msg, "(susso)", &id, &uid, &user, &seat, &path)) > 0) {
                if (!trust_text_valid(id, 256) || !*id)
                        goto fail;
                track_session(m, id, path, -1);
        }
        if (r < 0 || sd_bus_message_exit_container(msg) < 0 || sd_bus_message_at_end(msg, true) <= 0)
                goto fail;
        return 0;
fail:
        forget_sessions(m);
        schedule_session_retry(m);
        return 0;
}

static void enumerate_sessions(Manager *m) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *request = NULL;

        m->session_query = sd_bus_slot_unref(m->session_query);
        m->session_retry = sd_event_source_unref(m->session_retry);
        m->query_generation = m->session_generation;
        if (!m->bus ||
            sd_bus_message_new_method_call(m->bus, &request, "org.freedesktop.login1",
                                          "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "ListSessions") < 0 ||
            sd_bus_call_async(m->bus, &m->session_query, request, on_sessions, m, 2000000) < 0)
                schedule_session_retry(m);
}

static int on_logind_owner(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name, *old_owner, *new_owner;

        if (sd_bus_message_read(msg, "sss", &name, &old_owner, &new_owner) <= 0 ||
            !streq(name, "org.freedesktop.login1") || streq(old_owner, new_owner))
                return 0;
        m->session_generation++;
        forget_sleep_state(m);
        forget_sessions(m);
        if (*new_owner) {
                query_preparing_for_sleep(m);
                enumerate_sessions(m);
        }
        return 0;
}

static int on_bus_disconnected(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        forget_sleep_state(m);
        forget_sessions(m);
        return sd_event_exit(m->event, EXIT_FAILURE);
}

static int on_match_installed(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        if (sd_bus_message_is_method_error(msg, NULL))
                return on_bus_disconnected(msg, userdata, error);
        return 0;
}

static int on_reconnect(sd_event_source *source, uint64_t usec, void *userdata) {
        Manager *m = userdata;

        m->reconnect = sd_event_source_unref(m->reconnect);
        setup_logind(m);
        return 0;
}

static void setup_logind(Manager *m) {
        int r;

        forget_sleep_state(m);
        r = sd_bus_open_system(&m->bus);
        if (r < 0 || sd_bus_attach_event(m->bus, m->event, SD_EVENT_PRIORITY_NORMAL) < 0)
                goto fail;
        r = sd_bus_match_signal_async(m->bus, NULL, "org.freedesktop.login1", NULL,
                                     "org.freedesktop.DBus.Properties", "PropertiesChanged",
                                     on_props, on_match_installed, m);
        if (r < 0)
                goto fail;
        r = sd_bus_match_signal_async(m->bus, NULL, "org.freedesktop.login1", "/org/freedesktop/login1",
                                     "org.freedesktop.login1.Manager", "SessionNew",
                                     on_session_new, on_match_installed, m);
        if (r < 0)
                goto fail;
        r = sd_bus_match_signal_async(m->bus, NULL, "org.freedesktop.login1", "/org/freedesktop/login1",
                                     "org.freedesktop.login1.Manager", "SessionRemoved",
                                     on_session_removed, on_match_installed, m);
        if (r < 0)
                goto fail;
        r = sd_bus_match_signal_async(m->bus, NULL, "org.freedesktop.login1", "/org/freedesktop/login1",
                                     "org.freedesktop.login1.Manager", "PrepareForSleep",
                                     on_prepare_for_sleep, on_match_installed, m);
        if (r < 0)
                goto fail;
        r = sd_bus_match_signal_async(m->bus, NULL, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                     "org.freedesktop.DBus", "NameOwnerChanged",
                                     on_logind_owner, on_match_installed, m);
        if (r < 0)
                goto fail;
        r = sd_bus_match_signal(m->bus, NULL, NULL, "/org/freedesktop/DBus/Local",
                               "org.freedesktop.DBus.Local", "Disconnected", on_bus_disconnected, m);
        if (r < 0)
                goto fail;
        enumerate_sessions(m);
        query_preparing_for_sleep(m);
        return;
fail:
        forget_sleep_state(m);
        forget_sessions(m);
        m->bus = sd_bus_flush_close_unref(m->bus);
        (void) sd_event_add_time(m->event, &m->reconnect, CLOCK_BOOTTIME, now_boottime() + 5000000,
                                0, on_reconnect, m);
}

/* --- authentication events --------------------------------------------------- */

#define AUTH_EVENTS_MAX 64
#define AUTH_USER_MAX 256
#define AUTH_SERVICE_MAX 128
#define AUTH_ENDPOINT_MAX 256
#define AUTH_PHASE_MAX 32
#define AUTH_METHOD_MAX 128
#define AUTH_RESULT_MAX 16
#define AUTH_SESSION_MAX 256

static void auth_event_free(AuthEvent *e) {
        free(e->user); free(e->service); free(e->tty); free(e->rhost);
        free(e->phase); free(e->method); free(e->result); free(e->session);
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
                SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(e->session ?: "")),
                SD_JSON_BUILD_PAIR("qualifiesForFreshness", SD_JSON_BUILD_BOOLEAN(
                                e->qualifies_for_freshness)),
                SD_JSON_BUILD_PAIR("realtimeUSec", SD_JSON_BUILD_UNSIGNED(e->timestamp.realtime_usec)),
                SD_JSON_BUILD_PAIR("evidenceQuality", SD_JSON_BUILD_STRING("declared")));
}

static int json_string_parameter(
                sd_json_variant *parameters,
                const char *key,
                size_t max,
                const char **ret) {

        sd_json_variant *p = sd_json_variant_by_key(parameters, key);

        if (!p || !sd_json_variant_is_string(p))
                return -EINVAL;
        *ret = sd_json_variant_string(p);
        return trust_text_valid(*ret, max) ? 0 : -EINVAL;
}

static void append_auth_event(Manager *m, AuthEvent *e) {
        e->next = m->events;
        m->events = e;
        m->n_events++;
        sd_journal_send("MESSAGE=platform-authentication event recorded",
                        "PLATFORMD_EVENT=auth-event",
                        "PLATFORMD_AUTH_USER=%s", e->user ?: "",
                        "PLATFORMD_AUTH_SESSION=%s", e->session ?: "",
                        "PLATFORMD_AUTH_METHOD=%s", e->method ?: "",
                        "PLATFORMD_AUTH_RESULT=%s", e->result ?: "",
                        "PLATFORMD_AUTH_FRESHNESS=%s",
                        e->qualifies_for_freshness ? "yes" : "no",
                        NULL);
        if (m->n_events > AUTH_EVENTS_MAX) {
                AuthEvent **pp = &m->events;

                while ((*pp)->next)
                        pp = &(*pp)->next;
                auth_event_free(*pp);
                *pp = NULL;
                m->n_events--;
        }
}

static int vl_submit_auth_event(sd_varlink *link, sd_json_variant *parameters,
                                sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = manager_instance;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *empty = NULL, *payload = NULL;
        _cleanup_free_ char *class = NULL, *session_user = NULL;
        const char *user, *service, *tty, *rhost, *phase, *method, *result, *session;
        TrackedSession *tracked;
        sd_json_variant *p;
        AuthEvent *e = NULL;
        uint64_t uid_value;
        uid_t peer = (uid_t) -1;
        uid_t session_uid;
        bool class_eligible;
        int r;

        if (sd_varlink_get_peer_uid(link, &peer) < 0 || peer != 0)
                return sd_varlink_error(link, "io.platformd.Trust.PermissionDenied", NULL);

        if (json_string_parameter(parameters, "user", AUTH_USER_MAX, &user) < 0 || !*user)
                return sd_varlink_error_invalid_parameter_name(link, "user");
        if (json_string_parameter(parameters, "pamService", AUTH_SERVICE_MAX, &service) < 0 ||
            !*service)
                return sd_varlink_error_invalid_parameter_name(link, "pamService");
        if (json_string_parameter(parameters, "tty", AUTH_ENDPOINT_MAX, &tty) < 0)
                return sd_varlink_error_invalid_parameter_name(link, "tty");
        if (json_string_parameter(parameters, "remoteHost", AUTH_ENDPOINT_MAX, &rhost) < 0)
                return sd_varlink_error_invalid_parameter_name(link, "remoteHost");
        if (json_string_parameter(parameters, "phase", AUTH_PHASE_MAX, &phase) < 0 ||
            (!streq(phase, "session") && !streq(phase, "verify")))
                return sd_varlink_error_invalid_parameter_name(link, "phase");
        if (json_string_parameter(parameters, "declaredMethod", AUTH_METHOD_MAX, &method) < 0 ||
            !*method)
                return sd_varlink_error_invalid_parameter_name(link, "declaredMethod");
        if (json_string_parameter(parameters, "result", AUTH_RESULT_MAX, &result) < 0 ||
            (!streq(result, "success") && !streq(result, "failure")))
                return sd_varlink_error_invalid_parameter_name(link, "result");
        if (json_string_parameter(parameters, "sessionId", AUTH_SESSION_MAX, &session) < 0 ||
            !*session)
                return sd_varlink_error_invalid_parameter_name(link, "sessionId");

        p = sd_json_variant_by_key(parameters, "uid");
        if (!p || !sd_json_variant_is_unsigned(p))
                return sd_varlink_error_invalid_parameter_name(link, "uid");
        uid_value = sd_json_variant_unsigned(p);
        if (uid_value > (uint64_t) (uid_t) -2)
                return sd_varlink_error_invalid_parameter_name(link, "uid");

        if (sd_session_get_uid(session, &session_uid) < 0)
                return sd_varlink_error(link, "io.platformd.Trust.NoSuchSession", NULL);
        if (session_uid != (uid_t) uid_value)
                return sd_varlink_error(link, "io.platformd.Trust.InvalidAuthEvent", NULL);
        if (sd_session_get_username(session, &session_user) < 0 || !streq(user, session_user))
                return sd_varlink_error(link, "io.platformd.Trust.InvalidAuthEvent", NULL);

        class_eligible =
                sd_session_get_class(session, &class) >= 0 &&
                trust_session_class_allowed(class);
        tracked = ensure_tracked_session(m, session);

        e = calloc(1, sizeof *e);
        if (!e)
                return -ENOMEM;
        e->user = strdup(user);
        e->service = strdup(service);
        e->tty = strdup(tty);
        e->rhost = strdup(rhost);
        e->phase = strdup(phase);
        e->method = strdup(method);
        e->result = strdup(result);
        e->session = strdup(session);
        if (!e->user || !e->service || !e->tty || !e->rhost || !e->phase ||
            !e->method || !e->result || !e->session) {
                auth_event_free(e);
                return -ENOMEM;
        }
        e->uid = (uid_t) uid_value;
        r = runtime_timestamp_now(&e->timestamp);
        if (r < 0) {
                auth_event_free(e);
                return r;
        }
        e->qualifies_for_freshness =
                tracked &&
                class_eligible &&
                m->preparing_for_sleep == 0 &&
                trust_auth_event_qualifies(service, phase, method, result);

        if (e->qualifies_for_freshness && tracked) {
                trust_session_record_verification(&tracked->state, e->timestamp.boottime_usec,
                                                   e->timestamp.realtime_usec);
        }
        append_auth_event(m, e);

        if (auth_event_to_json(e, &payload) < 0 ||
            sd_json_variant_set_field_unsigned(&payload, "peerUid", peer) < 0)
                m->runtime_log_incomplete = true;
        else
                record_runtime_event(m, &e->timestamp, "authentication", "io.platformd.Trust.SubmitAuthEvent",
                                     "declared", payload);

        if ((r = sd_json_variant_new_object(&empty, NULL, 0)) < 0)
                return r;
        return sd_varlink_reply(link, empty);
}

static bool verification_context_valid(sd_json_variant *context) {
        static const char * const fields[] = { "challengeHex", "audience", "operationDigestHex" };

        if (!sd_json_variant_is_object(context) || sd_json_variant_elements(context) != 6)
                return false;
        for (size_t i = 0; i < sizeof fields / sizeof fields[0]; i++) {
                sd_json_variant *value = sd_json_variant_by_key(context, fields[i]);
                const char *text;
                size_t n;

                if (!sd_json_variant_is_string(value))
                        return false;
                text = sd_json_variant_string(value);
                n = strlen(text);
                if (i == 1) {
                        if (n == 0 || n > 256)
                                return false;
                        for (size_t j = 0; j < n; j++)
                                if ((unsigned char) text[j] < 0x20 || (unsigned char) text[j] > 0x7e)
                                        return false;
                } else {
                        if (n != 64)
                                return false;
                        for (size_t j = 0; j < n; j++)
                                if (!((text[j] >= '0' && text[j] <= '9') || (text[j] >= 'a' && text[j] <= 'f')))
                                        return false;
                }
        }
        return true;
}

static bool verification_unsigned(sd_json_variant *value) {
        sd_json_variant_type_t type = sd_json_variant_type(value);

        return (type == SD_JSON_VARIANT_INTEGER || type == SD_JSON_VARIANT_UNSIGNED) &&
               sd_json_variant_is_unsigned(value);
}

static int vl_submit_verification_event(sd_varlink *link, sd_json_variant *parameters,
                                       sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = manager_instance;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *empty = NULL, *payload = NULL;
        _cleanup_free_ char *class = NULL, *session_user = NULL, *session_state = NULL;
        const char *user, *session;
        sd_json_variant *p, *context;
        uint64_t uid_value, verification_boot, verification_real;
        RuntimeTimestamp now;
        TrackedSession *tracked;
        AuthEvent *e;
        uid_t peer, session_uid;
        int r;

        if (sd_varlink_get_peer_uid(link, &peer) < 0 || peer != 0)
                return sd_varlink_error(link, "io.platformd.Trust.PermissionDenied", NULL);
        if (json_string_parameter(parameters, "user", AUTH_USER_MAX, &user) < 0 || !*user)
                return sd_varlink_error_invalid_parameter_name(link, "user");
        if (json_string_parameter(parameters, "sessionId", AUTH_SESSION_MAX, &session) < 0 || !*session)
                return sd_varlink_error_invalid_parameter_name(link, "sessionId");
        p = sd_json_variant_by_key(parameters, "uid");
        if (!verification_unsigned(p) || (uid_value = sd_json_variant_unsigned(p)) > (uint64_t) (uid_t) -2)
                return sd_varlink_error_invalid_parameter_name(link, "uid");
        context = sd_json_variant_by_key(parameters, "context");
        if (!verification_context_valid(context))
                return sd_varlink_error_invalid_parameter_name(link, "context");
        p = sd_json_variant_by_key(parameters, "verificationBoottimeUSec");
        if (!verification_unsigned(p) || (verification_boot = sd_json_variant_unsigned(p)) == 0)
                return sd_varlink_error_invalid_parameter_name(link, "verificationBoottimeUSec");
        p = sd_json_variant_by_key(parameters, "verificationRealtimeUSec");
        if (!verification_unsigned(p) || (verification_real = sd_json_variant_unsigned(p)) == 0)
                return sd_varlink_error_invalid_parameter_name(link, "verificationRealtimeUSec");
        r = runtime_timestamp_now(&now);
        if (r < 0)
                return r;
        if (verification_boot > now.boottime_usec || now.boottime_usec - verification_boot >= UINT64_C(120000000) ||
            verification_real > now.realtime_usec || now.realtime_usec - verification_real >= UINT64_C(120000000))
                return sd_varlink_error(link, "io.platformd.Trust.InvalidAuthEvent", NULL);
        if (sd_session_get_uid(session, &session_uid) < 0)
                return sd_varlink_error(link, "io.platformd.Trust.NoSuchSession", NULL);
        if (session_uid != (uid_t) uid_value ||
            sd_session_get_username(session, &session_user) < 0 || !streq(user, session_user) ||
            sd_session_get_class(session, &class) < 0 || !trust_session_class_allowed(class) ||
            sd_session_get_state(session, &session_state) < 0 || !streq(session_state, "active") ||
            sd_session_is_active(session) <= 0 || sd_session_is_remote(session) != 0)
                return sd_varlink_error(link, "io.platformd.Trust.InvalidAuthEvent", NULL);
        tracked = ensure_tracked_session(m, session);
        if (!tracked || tracked->state.lock_state != 0 || m->preparing_for_sleep != 0 ||
            verification_boot <= m->verification_invalidated_usec ||
            verification_boot <= tracked->verification_invalidated_usec)
                return sd_varlink_error(link, "io.platformd.Trust.InvalidAuthEvent", NULL);

        e = calloc(1, sizeof *e);
        if (!e)
                return -ENOMEM;
        e->user = strdup(user);
        e->service = strdup("platformd-verify");
        e->phase = strdup("verify");
        e->method = strdup("platformd-verify");
        e->result = strdup("success");
        e->session = strdup(session);
        e->uid = (uid_t) uid_value;
        e->timestamp = now;
        e->qualifies_for_freshness = true;
        if (!e->user || !e->service || !e->phase || !e->method || !e->result || !e->session) {
                auth_event_free(e);
                return -ENOMEM;
        }
        r = auth_event_to_json(e, &payload);
        if (r >= 0)
                r = sd_json_variant_merge_objectbo(&payload,
                        SD_JSON_BUILD_PAIR_UNSIGNED("peerUid", peer),
                        SD_JSON_BUILD_PAIR_VARIANT("context", context),
                        SD_JSON_BUILD_PAIR_UNSIGNED("verificationBoottimeUSec", verification_boot),
                        SD_JSON_BUILD_PAIR_UNSIGNED("verificationRealtimeUSec", verification_real));
        if (r >= 0)
                r = sd_json_variant_new_object(&empty, NULL, 0);
        if (r < 0) {
                auth_event_free(e);
                return r;
        }
        if (verification_boot > tracked->state.last_verification_boottime_usec) {
                trust_session_record_verification(&tracked->state, verification_boot, verification_real);
        }
        append_auth_event(m, e);
        record_runtime_event(m, &now, "authentication", "io.platformd.Trust.SubmitVerificationEvent", "declared", payload);
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

static int backend_reply(sd_varlink *link, sd_json_variant *parameters) {
        return sd_json_buildo(&manager_instance->backend_result,
                             SD_JSON_BUILD_PAIR_VARIANT("parameters", parameters));
}

static int backend_error(sd_varlink *link, const char *error, sd_json_variant *parameters) {
        return sd_json_buildo(&manager_instance->backend_result,
                             SD_JSON_BUILD_PAIR_STRING("error", error),
                             SD_JSON_BUILD_PAIR_VARIANT("parameters", parameters));
}

static int backend_invalid(sd_varlink *link, const char *name) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        int r;

        r = sd_json_buildo(&parameters, SD_JSON_BUILD_PAIR_STRING("parameter", name));
        return r < 0 ? r : backend_error(link, "org.varlink.service.InvalidParameter", parameters);
}

static int vl_get_runtime_log_run(sd_varlink *link, sd_json_variant *parameters,
                              sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = manager_instance;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *arr = NULL, *result = NULL;
        char current[65] = "";
        uint8_t nvval[32];
        bool complete;
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
        complete = !m->runtime_log_incomplete;
        if (attest_nv_read(nvval) == 0)
                for (int i = 0; i < 32; i++)
                        snprintf(current + 2 * i, 3, "%02x", nvval[i]);
        else
                complete = false;
        complete = complete && streq(current, m->runtime_tail ? m->runtime_tail->digest : m->baseline_runtime);
        r = sd_json_buildo(&result,
                SD_JSON_BUILD_PAIR_STRING("format", RUNTIME_LOG_FORMAT),
                SD_JSON_BUILD_PAIR("nvIndex", SD_JSON_BUILD_STRING("0x01800001")),
                SD_JSON_BUILD_PAIR("baseline", SD_JSON_BUILD_STRING(m->baseline_runtime)),
                SD_JSON_BUILD_PAIR("current", SD_JSON_BUILD_STRING(current)),
                SD_JSON_BUILD_PAIR("events", SD_JSON_BUILD_VARIANT(arr)),
                SD_JSON_BUILD_PAIR("complete", SD_JSON_BUILD_BOOLEAN(complete)),
                SD_JSON_BUILD_PAIR("evidenceQuality", SD_JSON_BUILD_STRING(
                                !complete ? "incomplete" :
                                m->n_runtime > 0 ? "measured" : "observed")));
        if (r < 0)
                return r;
        return backend_reply(link, result);
}

/* --- attestation ------------------------------------------------------------- */

/* Producing a TPM quote, NV certification, or credential activation is a
 * signing operation on a shared device. If it were open to every local
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
 * the PCR values. Read to EOF because the log is often larger than one buffer and a
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
                if (n == 0) {   /* Only a clean EOF is complete evidence. */
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

static int vl_attest_run(sd_varlink *link, sd_json_variant *parameters,
                     sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        _cleanup_free_ uint8_t *nonce = NULL, *ak = NULL, *quoted = NULL, *sig = NULL;
        _cleanup_free_ char *ak_hex = NULL, *quoted_hex = NULL, *sig_hex = NULL, *evlog_hex = NULL;
        size_t nonce_len = 0, ak_len = 0, quoted_len = 0, sig_len = 0;
        sd_json_variant *p;
        int r;


        p = sd_json_variant_by_key(parameters, "nonceHex");
        if (!p || !sd_json_variant_is_string(p) ||
            hex_decode(sd_json_variant_string(p), &nonce, &nonce_len) < 0 || nonce_len > 64)
                return backend_invalid(link, "nonceHex");

        r = attest_quote(nonce, nonce_len, &ak, &ak_len, &quoted, &quoted_len, &sig, &sig_len);
        if (r == -ENOTSUP || r == -ENODEV)
                return backend_error(link, "io.platformd.Trust.AttestationUnsupported", NULL);
        if (r < 0)
                return backend_error(link, "io.platformd.Trust.AttestationFailed", NULL);

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
        return backend_reply(link, result);
}

/* The envelope is unsigned. Only the embedded TPM structures are signed. */
static int vl_get_attestation_token_run(sd_varlink *link, sd_json_variant *parameters,
                                    sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = manager_instance;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *eat = NULL, *result = NULL,
                *pcrs = NULL, *revents = NULL, *measurements = NULL,
                *quote_m = NULL, *boot_m = NULL, *runtime_m = NULL, *cnf = NULL, *observations = NULL;
        _cleanup_free_ uint8_t *nonce = NULL, *ak = NULL, *quoted = NULL, *sig = NULL,
                *nv_ak = NULL, *nv_ci = NULL, *nv_sig = NULL, *nv_public = NULL;
        _cleanup_free_ char *ak_hex = NULL, *quoted_hex = NULL, *sig_hex = NULL, *eat_str = NULL,
                *nv_ci_hex = NULL, *nv_sig_hex = NULL, *nv_public_hex = NULL;
        size_t nonce_len = 0, ak_len = 0, quoted_len = 0, sig_len = 0,
                nv_ak_len = 0, nv_ci_len = 0, nv_sig_len = 0, nv_public_len = 0;
        char machine_str[SD_ID128_STRING_MAX], nv_current[65] = "";
        uint8_t nvval[32];
        const char *nonce_hex, *sb;
        sd_id128_t machine;
        sd_json_variant *p;
        int r;

        if (m->runtime_log_incomplete)
                return backend_error(link, "io.platformd.Trust.AttestationFailed", NULL);

        p = sd_json_variant_by_key(parameters, "nonceHex");
        if (!p || !sd_json_variant_is_string(p) ||
            hex_decode((nonce_hex = sd_json_variant_string(p)), &nonce, &nonce_len) < 0 || nonce_len > 64)
                return backend_invalid(link, "nonceHex");

        r = attest_quote(nonce, nonce_len, &ak, &ak_len, &quoted, &quoted_len, &sig, &sig_len);
        if (r == -ENOTSUP || r == -ENODEV)
                return backend_error(link, "io.platformd.Trust.AttestationUnsupported", NULL);
        if (r < 0)
                return backend_error(link, "io.platformd.Trust.AttestationFailed", NULL);
        if (!(ak_hex = hex_encode(ak, ak_len)) ||
            !(quoted_hex = hex_encode(quoted, quoted_len)) ||
            !(sig_hex = hex_encode(sig, sig_len)))
                return -ENOMEM;

        /* AK-certify the runtime NV log with the same primary key and nonce as
         * the boot quote. Partial runtime evidence is not an attestation. */
        if (attest_nv_certify(nonce, nonce_len, &nv_ak, &nv_ak_len,
                              &nv_ci, &nv_ci_len, &nv_sig, &nv_sig_len) < 0 ||
            nv_ak_len != ak_len || memcmp(nv_ak, ak, ak_len) != 0 ||
            !(nv_ci_hex = hex_encode(nv_ci, nv_ci_len)) ||
            !(nv_sig_hex = hex_encode(nv_sig, nv_sig_len)) ||
            attest_nv_read(nvval) < 0 ||
            attest_nv_public(&nv_public, &nv_public_len) < 0 ||
            !(nv_public_hex = hex_encode(nv_public, nv_public_len)))
                return backend_error(link, "io.platformd.Trust.AttestationFailed", NULL);
        for (int i = 0; i < 32; i++)
                snprintf(nv_current + 2 * i, 3, "%02x", nvval[i]);
        if (!streq(nv_current, m->runtime_tail ? m->runtime_tail->digest : m->baseline_runtime))
                return backend_error(link, "io.platformd.Trust.AttestationFailed", NULL);

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
                r = sd_json_buildo(&o,
                        SD_JSON_BUILD_PAIR("description", SD_JSON_BUILD_STRING(e->desc ?: "")),
                        SD_JSON_BUILD_PAIR("digest", SD_JSON_BUILD_STRING(e->digest)),
                        SD_JSON_BUILD_PAIR("realtimeUSec", SD_JSON_BUILD_UNSIGNED(e->when)));
                if (r < 0)
                        return r;
                r = sd_json_variant_append_array(&revents, o);
                if (r < 0)
                        return r;
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
                        SD_JSON_BUILD_PAIR_STRING("format", RUNTIME_LOG_FORMAT),
                        SD_JSON_BUILD_PAIR("nvIndex", SD_JSON_BUILD_STRING("0x01800001")),
                        SD_JSON_BUILD_PAIR("baseline", SD_JSON_BUILD_STRING(m->baseline_runtime)),
                        SD_JSON_BUILD_PAIR("current", SD_JSON_BUILD_STRING(nv_current)),
                        SD_JSON_BUILD_PAIR("certifyInfo", SD_JSON_BUILD_STRING(nv_ci_hex ?: "")),
                        SD_JSON_BUILD_PAIR("nvPublicHex", SD_JSON_BUILD_STRING(nv_public_hex)),
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

        r = sd_json_buildo(&observations,
                          SD_JSON_BUILD_PAIR_STRING("machineId", machine_str),
                          SD_JSON_BUILD_PAIR_UNSIGNED("realtimeUSec", now_real()),
                          SD_JSON_BUILD_PAIR_STRING("secureBoot", sb));
        if (r < 0)
                return r;
        r = sd_json_buildo(&eat,
                SD_JSON_BUILD_PAIR_STRING("profile", "io.platformd.Trust.Attestation.v2"),
                SD_JSON_BUILD_PAIR_STRING("nonceHex", nonce_hex),
                SD_JSON_BUILD_PAIR_VARIANT("localAssertions", observations),
                SD_JSON_BUILD_PAIR("attestationKey", SD_JSON_BUILD_VARIANT(cnf)),
                SD_JSON_BUILD_PAIR("measurements", SD_JSON_BUILD_VARIANT(measurements)));
        if (r < 0)
                return r;
        if ((r = sd_json_variant_format(eat, SD_JSON_FORMAT_NEWLINE, &eat_str)) < 0)
                return r;

        r = sd_json_buildo(&result,
                SD_JSON_BUILD_PAIR("eat", SD_JSON_BUILD_STRING(eat_str)),
                SD_JSON_BUILD_PAIR("format", SD_JSON_BUILD_STRING("application/vnd.platformd.attestation+json")),
                SD_JSON_BUILD_PAIR("evidenceQuality", SD_JSON_BUILD_STRING("measured")));
        if (r < 0)
                return r;
        sd_journal_send("MESSAGE=attestation evidence produced", "PLATFORMD_EVENT=attest", NULL);
        return backend_reply(link, result);
}

/* --- Attestation enrollment inputs and credential activation ---------------- */

static int vl_get_enrollment_run(sd_varlink *link, sd_json_variant *parameters,
                             sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        _cleanup_free_ uint8_t *ek = NULL, *ek_cert = NULL, *ak = NULL, *ak_name = NULL;
        _cleanup_free_ char *ek_hex = NULL, *ek_cert_hex = NULL, *ak_hex = NULL, *ak_name_hex = NULL;
        size_t ek_len = 0, ek_cert_len = 0, ak_len = 0, ak_name_len = 0;
        int r;


        r = attest_get_enrollment(&ek, &ek_len, &ek_cert, &ek_cert_len,
                                  &ak, &ak_len, &ak_name, &ak_name_len);
        if (r == -ENOTSUP || r == -ENODEV)
                return backend_error(link, "io.platformd.Trust.AttestationUnsupported", NULL);
        if (r < 0)
                return backend_error(link, "io.platformd.Trust.AttestationFailed", NULL);

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
        return backend_reply(link, result);
}

static int vl_activate_credential_run(sd_varlink *link, sd_json_variant *parameters,
                                  sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        _cleanup_free_ uint8_t *cred = NULL, *secret = NULL, *challenge = NULL;
        _cleanup_free_ char *challenge_hex = NULL;
        size_t cred_len = 0, secret_len = 0, challenge_len = 0;
        sd_json_variant *pc, *ps;
        int r;


        pc = sd_json_variant_by_key(parameters, "credentialHex");
        ps = sd_json_variant_by_key(parameters, "secretHex");
        if (!pc || !sd_json_variant_is_string(pc) ||
            hex_decode(sd_json_variant_string(pc), &cred, &cred_len) < 0)
                return backend_invalid(link, "credentialHex");
        if (!ps || !sd_json_variant_is_string(ps) ||
            hex_decode(sd_json_variant_string(ps), &secret, &secret_len) < 0)
                return backend_invalid(link, "secretHex");

        r = attest_activate_credential(cred, cred_len, secret, secret_len, &challenge, &challenge_len);
        if (r == -ENOTSUP || r == -ENODEV)
                return backend_error(link, "io.platformd.Trust.AttestationUnsupported", NULL);
        if (r < 0)
                return backend_error(link, "io.platformd.Trust.AttestationFailed", NULL);

        if (!(challenge_hex = hex_encode(challenge, challenge_len)))
                return -ENOMEM;
        r = sd_json_buildo(&result,
                SD_JSON_BUILD_PAIR("challengeHex", SD_JSON_BUILD_STRING(challenge_hex)),
                SD_JSON_BUILD_PAIR("evidenceQuality", SD_JSON_BUILD_STRING("measured")));
        if (r < 0)
                return r;
        sd_journal_send("MESSAGE=credential activated (AK enrollment)", "PLATFORMD_EVENT=enroll", NULL);
        return backend_reply(link, result);
}

typedef struct BackendRequest {
        struct BackendRequest *next;
        Worker *worker;
        sd_varlink *link;
        sd_json_variant *parameters;
        sd_varlink_method_t method;
        RuntimeEvent *event;
        uint64_t deadline;
        uid_t peer;
} BackendRequest;

static int backend_start_next(Manager *m);

static int backend_run(void *userdata, sd_json_variant **ret) {
        BackendRequest *q = userdata;
        Manager *m = manager_instance;
        _cleanup_free_ char *current = NULL;
        uint8_t value[32];
        int r;

        if (q->method) {
                r = q->method(NULL, q->parameters, 0, m);
                *ret = m->backend_result;
                m->backend_result = NULL;
                return r;
        }
        if (!q->event) {
                r = attest_nv_prepare();
                if (r < 0)
                        return r;
        }
        r = attest_nv_read(value);
        if (r < 0)
                return r;
        if (q->event) {
                _cleanup_free_ uint8_t *previous = NULL;
                const char *expected = m->runtime_tail ? m->runtime_tail->digest : m->baseline_runtime;
                uint8_t digest[32], event_digest[32];
                size_t size = 0;

                if (hex_decode(expected, &previous, &size) < 0 || size != 32 ||
                    memcmp(value, previous, 32) != 0)
                        return -ESTALE;
                r = runtime_event_replay(previous, q->event->desc, digest);
                if (r < 0)
                        return r;
                r = runtime_event_digest(q->event->desc, event_digest);
                if (r < 0)
                        return r;
                r = attest_nv_extend(event_digest, sizeof event_digest, value);
                if (r < 0)
                        return r;
                if (memcmp(value, digest, sizeof digest) != 0)
                        return -ESTALE;
        }
        current = hex_encode(value, sizeof value);
        return current ? sd_json_buildo(ret, SD_JSON_BUILD_PAIR_STRING("current", current)) : -ENOMEM;
}

static void backend_free(BackendRequest *q) {
        if (!q)
                return;
        worker_free(q->worker);
        sd_varlink_unref(q->link);
        sd_json_variant_unref(q->parameters);
        if (q->event) {
                free(q->event->desc);
                free(q->event);
        }
        free(q);
}

static void backend_finish(Manager *m, BackendRequest *q, int error, sd_json_variant *result) {
        if (q->method) {
                sd_json_variant *name = sd_json_variant_by_key(result, "error");
                sd_json_variant *parameters = sd_json_variant_by_key(result, "parameters");

                if (q->link) {
                        if (error < 0)
                                (void) sd_varlink_error_errno(q->link, error);
                        else if (sd_json_variant_is_string(name))
                                (void) sd_varlink_error(q->link, sd_json_variant_string(name), parameters);
                        else if (parameters)
                                (void) sd_varlink_reply(q->link, parameters);
                        else
                                (void) sd_varlink_error_errno(q->link, -EBADMSG);
                }
        } else {
                sd_json_variant *value = sd_json_variant_by_key(result, "current");
                const char *current = sd_json_variant_is_string(value) ? sd_json_variant_string(value) : "";

                if (error < 0 || strlen(current) != 64)
                        m->runtime_log_incomplete = true;
                else if (q->event) {
                        RuntimeEvent *e = q->event;

                        q->event = NULL;
                        memcpy(e->digest, current, sizeof e->digest);
                        if (m->runtime_tail)
                                m->runtime_tail->next = e;
                        else
                                m->runtime_log = e;
                        m->runtime_tail = e;
                        m->n_runtime++;
                        if (m->n_runtime > RUNTIME_LOG_MAX) {
                                e = m->runtime_log;
                                memcpy(m->baseline_runtime, e->digest, sizeof m->baseline_runtime);
                                m->runtime_log = e->next;
                                free(e->desc);
                                free(e);
                                m->n_runtime--;
                        }
                } else
                        memcpy(m->baseline_runtime, current, sizeof m->baseline_runtime);
        }
        m->backend_head = q->next;
        if (!m->backend_head)
                m->backend_tail = NULL;
        backend_free(q);
}

static void backend_done(int error, sd_json_variant *result, void *userdata) {
        Manager *m = manager_instance;

        backend_finish(m, userdata, error, result);
        (void) backend_start_next(m);
}

static int backend_start_next(Manager *m) {
        while (m->backend_head && !m->backend_head->worker) {
                BackendRequest *q = m->backend_head;
                uint64_t now = now_boottime();
                int r;

                r = now >= q->deadline ? -ETIMEDOUT :
                        worker_start(m->event, q->deadline - now, backend_run, backend_done, q, &q->worker);
                if (r >= 0)
                        return 0;
                backend_finish(m, q, r, NULL);
        }
        return 0;
}

static int backend_enqueue(Manager *m, sd_varlink *link, sd_json_variant *parameters,
                           sd_varlink_method_t method, const char *description, uint64_t realtime_usec) {
        BackendRequest *q;
        uid_t peer = (uid_t) -1;
        unsigned total = 0, owned = 0;

        if (link && sd_varlink_get_peer_uid(link, &peer) < 0)
                return -EIO;
        for (q = m->backend_head; q; q = q->next) {
                total++;
                owned += q->peer == peer;
        }
        if (total >= 64 || (link && owned >= 4))
                return -EBUSY;
        q = calloc(1, sizeof *q);
        if (!q)
                return -ENOMEM;
        q->link = sd_varlink_ref(link);
        q->parameters = sd_json_variant_ref(parameters);
        q->method = method;
        q->peer = peer;
        q->deadline = now_boottime() + 20000000;
        if (description) {
                q->event = calloc(1, sizeof *q->event);
                if (!q->event || !(q->event->desc = strdup(description))) {
                        backend_free(q);
                        return -ENOMEM;
                }
                q->event->when = realtime_usec;
        }
        if (m->backend_tail)
                m->backend_tail->next = q;
        else
                m->backend_head = q;
        m->backend_tail = q;
        (void) backend_start_next(m);
        return 1;
}

static void runtime_event_queue(Manager *m, const char *record, uint64_t realtime_usec) {
        if (backend_enqueue(m, NULL, NULL, NULL, record, realtime_usec) < 0)
                m->runtime_log_incomplete = true;
}

static int backend_request(sd_varlink *link, sd_json_variant *parameters,
                           sd_varlink_method_t method, bool privileged) {
        if (privileged && !peer_is_root(link))
                return sd_varlink_error(link, "io.platformd.Trust.PermissionDenied", NULL);
        return backend_enqueue(manager_instance, link, parameters, method, NULL, 0);
}

static void on_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Manager *m = userdata;

        for (IdentityRequest **p = &m->identity_requests; *p;) {
                IdentityRequest *q = *p;

                if (q->link != link) {
                        p = &q->next;
                        continue;
                }
                *p = q->next;
                identity_free(q);
        }
        for (BackendRequest *q = m->backend_head; q; q = q->next)
                if (q->link == link) {
                        q->link = sd_varlink_unref(q->link);
                        q->deadline = 0;
                }
}

static int vl_get_runtime_log(sd_varlink *link, sd_json_variant *parameters,
                       sd_varlink_method_flags_t flags, void *userdata) {
        return backend_request(link, parameters, vl_get_runtime_log_run, false);
}

static int vl_get_measured_boot(sd_varlink *link, sd_json_variant *parameters,
                               sd_varlink_method_flags_t flags, void *userdata) {
        return backend_request(link, parameters, vl_get_measured_boot_run, false);
}

static int vl_attest(sd_varlink *link, sd_json_variant *parameters,
                       sd_varlink_method_flags_t flags, void *userdata) {
        return backend_request(link, parameters, vl_attest_run, true);
}

static int vl_get_attestation_token(sd_varlink *link, sd_json_variant *parameters,
                       sd_varlink_method_flags_t flags, void *userdata) {
        return backend_request(link, parameters, vl_get_attestation_token_run, true);
}

static int vl_get_enrollment(sd_varlink *link, sd_json_variant *parameters,
                       sd_varlink_method_flags_t flags, void *userdata) {
        return backend_request(link, parameters, vl_get_enrollment_run, true);
}

static int vl_activate_credential(sd_varlink *link, sd_json_variant *parameters,
                       sd_varlink_method_flags_t flags, void *userdata) {
        return backend_request(link, parameters, vl_activate_credential_run, true);
}

/* --- Varlink server ---------------------------------------------------------- */

static int setup_varlink(Manager *m) {
        _cleanup_free_ char *addr = NULL, *lock = NULL;
        const char *dir;
        int r;

        dir = getenv("RUNTIME_DIRECTORY");
        if (!dir || !*dir)
                dir = getenv("PLATFORMD_TRUSTD_RUNTIME");
        if (!dir || !*dir)
                dir = "/run/platformd-trustd";
        (void) mkdir(dir, 0755);
        if (asprintf(&lock, "%s/lock", dir) < 0)
                return -ENOMEM;
        m->listener_lock = open(lock, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (m->listener_lock < 0 || flock(m->listener_lock, LOCK_EX | LOCK_NB) < 0)
                return -errno;
        if (asprintf(&addr, "%s/io.platformd.Trust", dir) < 0)
                return -ENOMEM;

        if ((r = sd_varlink_server_new(&m->varlink, 0)) < 0)
                return r;
        (void) sd_varlink_server_set_description(m->varlink, "platformd-trustd");
        sd_varlink_server_set_userdata(m->varlink, m);
        if ((r = sd_varlink_server_bind_disconnect(m->varlink, on_disconnect)) < 0)
                return r;
        if ((r = sd_varlink_server_add_interface(m->varlink, &vl_interface_io_platformd_Trust)) < 0 ||
            (r = sd_varlink_server_set_info(m->varlink, "platformd", "platformd-trustd", PROGRAM_VERSION,
                                           "https://github.com/CoastLineSec/platformd-trustd")) < 0)
                return r;
        if ((r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.GetBootEvidence", vl_get_boot_evidence)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.GetMeasuredBoot", vl_get_measured_boot)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.ListSessions", vl_list_sessions)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.GetSessionTrust", vl_get_session_trust)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.GetUserIdentity", vl_get_user_identity)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.EvaluatePolicy", vl_evaluate_policy)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.SubmitAuthEvent", vl_submit_auth_event)) < 0 ||
            (r = sd_varlink_server_bind_method(m->varlink, "io.platformd.Trust.SubmitVerificationEvent", vl_submit_verification_event)) < 0 ||
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

int main(int argc, char **argv) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        Manager manager = { .fresh_window = 300, .listener_lock = -1 };
        const char *fw;
        sigset_t ss;
        int r;

        if (argc == 2 && (streq(argv[1], "--help") || streq(argv[1], "-h"))) {
                puts("platformd-trustd [OPTIONS...]\n\nObserve platform authentication state.\n\n"
                     "  -h --help                    Show this help\n"
                     "     --version                 Show package version\n"
                     "     --initialize-runtime-log  Initialize the TPM runtime-log index");
                return EXIT_SUCCESS;
        }
        if (argc == 2 && streq(argv[1], "--version")) {
                puts("platformd-trustd " PROGRAM_VERSION);
                return EXIT_SUCCESS;
        }
        if (argc == 2 && streq(argv[1], "--initialize-runtime-log")) {
                r = geteuid() == 0 ? attest_nv_initialize() : -EPERM;
                if (r < 0)
                        fprintf(stderr, "Failed to initialize runtime log: %s\n", strerror(-r));
                return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        }
        if (argc != 1) {
                fprintf(stderr, "Unexpected argument: %s\n", argv[1]);
                return EXIT_FAILURE;
        }

        if ((r = sd_event_default(&event)) < 0) {
                sd_journal_print(LOG_ERR, "sd_event_default: %s", strerror(-r));
                return EXIT_FAILURE;
        }
        manager.event = event;
        manager_instance = &manager;

        fw = getenv("PLATFORMD_TRUST_FRESH_WINDOW_SEC");
        if (fw && *fw) {
                char *end;
                unsigned long long window;

                errno = 0;
                window = strtoull(fw, &end, 10);
                if (errno != 0 || fw[0] < '0' || fw[0] > '9' || *end || window == 0 || window > 86400) {
                        sd_journal_print(LOG_ERR, "Invalid authentication freshness window: %s", fw);
                        return EXIT_FAILURE;
                }
                manager.fresh_window = window;
        }

        sigemptyset(&ss);
        sigaddset(&ss, SIGTERM);
        sigaddset(&ss, SIGINT);
        sigaddset(&ss, SIGCHLD);
        sigprocmask(SIG_BLOCK, &ss, NULL);
        (void) sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
        (void) sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);

        if ((r = setup_varlink(&manager)) < 0) {
                sd_journal_print(LOG_ERR, "setup_varlink: %s", strerror(-r));
                sd_varlink_server_unref(manager.varlink);
                if (manager.listener_lock >= 0)
                        close(manager.listener_lock);
                return EXIT_FAILURE;
        }
        runtime_event_queue(&manager, NULL, 0);
        setup_logind(&manager);

        sd_notify(false, "READY=1\n"
                         "STATUS=platformd-trustd: observing platform-authentication state");
        sd_journal_print(LOG_INFO, "platformd-trustd started (observability)");

        r = sd_event_loop(event);

        while (manager.backend_head) {
                BackendRequest *q = manager.backend_head;
                manager.backend_head = q->next;
                backend_free(q);
        }
        while (manager.identity_requests) {
                IdentityRequest *q = manager.identity_requests;
                manager.identity_requests = q->next;
                identity_free(q);
        }
        forget_sleep_state(&manager);
        forget_sessions(&manager);
        sd_event_source_unref(manager.reconnect);
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
        sd_varlink_server_unref(manager.varlink);
        if (manager.listener_lock >= 0)
                close(manager.listener_lock);
        return r != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
