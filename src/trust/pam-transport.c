/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pam-transport.h"

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define _cleanup_(f) __attribute__((cleanup(f)))
#define PAM_TRUST_MESSAGE_MAX (64U * 1024U)
#define NSEC_PER_MSEC UINT64_C(1000000)
#define NSEC_PER_SEC UINT64_C(1000000000)

static void freep(void *p) {
        free(*(void **) p);
}

static void closep(int *fd) {
        if (*fd >= 0)
                close(*fd);
}

static int monotonic_now(uint64_t *ret) {
        struct timespec ts;

        if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
                return errno > 0 ? -errno : -EIO;

        *ret = (uint64_t) ts.tv_sec * NSEC_PER_SEC + (uint64_t) ts.tv_nsec;
        return 0;
}

static int deadline_remaining(uint64_t deadline) {
        uint64_t now;
        int r;

        r = monotonic_now(&now);
        if (r < 0)
                return r;
        if (now >= deadline)
                return -ETIMEDOUT;

        return (int) ((deadline - now + NSEC_PER_MSEC - 1) / NSEC_PER_MSEC);
}

static int wait_io(int fd, short events, uint64_t deadline) {
        struct pollfd pfd = { .fd = fd, .events = events };
        int r;

        for (;;) {
                r = deadline_remaining(deadline);
                if (r < 0)
                        return r;

                r = poll(&pfd, 1, r);
                if (r < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                if (r == 0)
                        return -ETIMEDOUT;
                if (pfd.revents & POLLNVAL)
                        return -EBADF;
                if (pfd.revents & (events | POLLHUP | POLLERR))
                        return 0;
        }
}

/* sd_varlink_call() cannot be used from every process that loads a PAM module. */
int pam_trust_call(const char *method, sd_json_variant *params, sd_json_variant **ret_reply) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *envelope = NULL, *reply = NULL;
        _cleanup_(freep) char *text = NULL, *buffer = NULL;
        _cleanup_(closep) int fd = -1;
        const struct sockaddr_un sa = {
                .sun_family = AF_UNIX,
                .sun_path = "/run/platformd-trustd/io.platformd.Trust",
        };
        struct ucred credentials;
        uint64_t deadline;
        socklen_t length;
        size_t size, offset = 0;
        int r;

        if (!ret_reply)
                return -EINVAL;
        *ret_reply = NULL;
        if (!method || !params)
                return -EINVAL;

        r = sd_json_buildo(&envelope,
                          SD_JSON_BUILD_PAIR("method", SD_JSON_BUILD_STRING(method)),
                          SD_JSON_BUILD_PAIR("parameters", SD_JSON_BUILD_VARIANT(params)));
        if (r < 0)
                return r;
        r = sd_json_variant_format(envelope, 0, &text);
        if (r < 0)
                return r;
        size = strlen(text) + 1;
        if (size > PAM_TRUST_MESSAGE_MAX)
                return -E2BIG;

        buffer = malloc(PAM_TRUST_MESSAGE_MAX);
        if (!buffer)
                return -ENOMEM;

        r = monotonic_now(&deadline);
        if (r < 0)
                return r;
        deadline += 5 * NSEC_PER_SEC;

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        for (;;) {
                r = deadline_remaining(deadline);
                if (r < 0)
                        return r;
                if (connect(fd, (const struct sockaddr *) &sa, sizeof(sa)) >= 0)
                        break;
                if (errno == EINTR)
                        continue;
                if (errno != EINPROGRESS && errno != EALREADY)
                        return -errno;

                r = wait_io(fd, POLLOUT, deadline);
                if (r < 0)
                        return r;

                length = sizeof(r);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &length) < 0)
                        return -errno;
                if (length != sizeof(r))
                        return -EIO;
                if (r != 0)
                        return -r;
                break;
        }

        length = sizeof(credentials);
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) < 0)
                return -errno;
        if (length != sizeof(credentials) || credentials.uid != 0 || credentials.pid <= 0)
                return -EACCES;

        while (offset < size) {
                ssize_t n;

                r = deadline_remaining(deadline);
                if (r < 0)
                        return r;

                n = send(fd, text + offset, size - offset, MSG_NOSIGNAL);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        if (errno != EAGAIN && errno != EWOULDBLOCK)
                                return -errno;
                        r = wait_io(fd, POLLOUT, deadline);
                        if (r < 0)
                                return r;
                        continue;
                }
                if (n == 0)
                        return -EIO;
                offset += (size_t) n;
        }

        offset = 0;
        for (;;) {
                char *end;
                ssize_t n;

                r = deadline_remaining(deadline);
                if (r < 0)
                        return r;
                if (offset >= PAM_TRUST_MESSAGE_MAX)
                        return -E2BIG;

                n = recv(fd, buffer + offset, PAM_TRUST_MESSAGE_MAX - offset, 0);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        if (errno != EAGAIN && errno != EWOULDBLOCK)
                                return -errno;
                        r = wait_io(fd, POLLIN, deadline);
                        if (r < 0)
                                return r;
                        continue;
                }
                if (n == 0)
                        return -EBADMSG;

                end = memchr(buffer + offset, 0, (size_t) n);
                offset += (size_t) n;
                if (!end)
                        continue;
                if (end != buffer + offset - 1)
                        return -EBADMSG;

                r = sd_json_parse(buffer, 0, &reply, NULL, NULL);
                if (r < 0)
                        return r;
                if (!sd_json_variant_is_object(reply))
                        return -EBADMSG;
                r = deadline_remaining(deadline);
                if (r < 0)
                        return r;

                *ret_reply = reply;
                reply = NULL;
                return 0;
        }
}
