/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pam-transport.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expression) do { \
        if (!(expression)) { \
                fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #expression); \
                abort(); \
        } \
} while (0)

typedef enum TestMode {
        TEST_NORMAL,
        TEST_SHORT_IO,
        TEST_UNTRUSTED,
        TEST_SHORT_CREDENTIALS,
        TEST_MISSING_CREDENTIALS,
        TEST_CLOSED,
        TEST_DEADLINE,
        TEST_CONNECT_REFUSED,
        TEST_ASYNC_REFUSED,
        TEST_ASYNC_SHORT_ERROR,
        TEST_ASYNC_MISSING_ERROR,
} TestMode;

int __real_connect(int fd, const struct sockaddr *address, socklen_t length);
int __real_getsockopt(int fd, int level, int option, void *value, socklen_t *length);
ssize_t __real_send(int fd, const void *buffer, size_t size, int flags);
ssize_t __real_recv(int fd, void *buffer, size_t size, int flags);
int __real_poll(struct pollfd *fds, nfds_t n, int timeout);

static struct sockaddr_un private_address = { .sun_family = AF_UNIX };
static TestMode test_mode;
static unsigned connect_calls, credential_calls, socket_error_calls, send_calls, recv_calls, poll_calls;
static int ready_fd;

static bool test_async_failure(void) {
        return test_mode == TEST_ASYNC_REFUSED || test_mode == TEST_ASYNC_SHORT_ERROR ||
               test_mode == TEST_ASYNC_MISSING_ERROR;
}

int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length) {
        const struct sockaddr_un *sa = (const struct sockaddr_un *) address;
        char ready;
        int r;

        CHECK(length == sizeof(*sa));
        CHECK(sa->sun_family == AF_UNIX);
        CHECK(strcmp(sa->sun_path, "/run/platformd-trustd/io.platformd.Trust") == 0);
        CHECK(fcntl(fd, F_GETFL) & O_NONBLOCK);
        CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC);
        connect_calls++;
        if (test_mode == TEST_CONNECT_REFUSED || test_async_failure()) {
                errno = test_mode == TEST_CONNECT_REFUSED ? ECONNREFUSED : EINPROGRESS;
                return -1;
        }
        if (test_mode == TEST_SHORT_IO && connect_calls == 1) {
                errno = EINTR;
                return -1;
        }

        r = __real_connect(fd, (const struct sockaddr *) &private_address, sizeof(private_address));
        CHECK(r == 0);
        if (test_mode == TEST_CLOSED)
                CHECK(read(ready_fd, &ready, 1) == 1);
        if (test_mode == TEST_SHORT_IO) {
                errno = EINPROGRESS;
                return -1;
        }
        return r;
}

int __wrap_getsockopt(int fd, int level, int option, void *value, socklen_t *length) {
        int r;

        if (test_async_failure()) {
                CHECK(level == SOL_SOCKET && option == SO_ERROR);
                CHECK(*length == sizeof(int));
                socket_error_calls++;
                if (test_mode == TEST_ASYNC_MISSING_ERROR) {
                        errno = EIO;
                        return -1;
                }
                *(int *) value = test_mode == TEST_ASYNC_REFUSED ? ECONNREFUSED : 0;
                if (test_mode == TEST_ASYNC_SHORT_ERROR)
                        (*length)--;
                return 0;
        }

        r = __real_getsockopt(fd, level, option, value, length);
        if (r < 0 || level != SOL_SOCKET || option != SO_PEERCRED)
                return r;

        credential_calls++;
        if (test_mode == TEST_MISSING_CREDENTIALS) {
                errno = ENOPROTOOPT;
                return -1;
        }
        if (test_mode == TEST_UNTRUSTED)
                CHECK(((struct ucred *) value)->uid != 0);
        else
                ((struct ucred *) value)->uid = 0;
        if (test_mode == TEST_SHORT_CREDENTIALS)
                (*length)--;
        return r;
}

ssize_t __wrap_send(int fd, const void *buffer, size_t size, int flags) {
        CHECK(credential_calls == 1);
        CHECK(flags & MSG_NOSIGNAL);
        send_calls++;
        if (test_mode == TEST_SHORT_IO) {
                if (send_calls == 1 || send_calls == 2) {
                        errno = send_calls == 1 ? EINTR : EAGAIN;
                        return -1;
                }
                if (size > 3)
                        size = 3;
        }
        return __real_send(fd, buffer, size, flags);
}

ssize_t __wrap_recv(int fd, void *buffer, size_t size, int flags) {
        recv_calls++;
        if (test_mode == TEST_SHORT_IO) {
                if (recv_calls == 1) {
                        errno = EINTR;
                        return -1;
                }
                if (size > 2)
                        size = 2;
        }
        return __real_recv(fd, buffer, size, flags);
}

int __wrap_poll(struct pollfd *fds, nfds_t n, int timeout) {
        poll_calls++;
        if (test_async_failure()) {
                CHECK(n == 1 && fds[0].events == POLLOUT);
                CHECK(timeout > 0 && timeout <= 5000);
                fds[0].revents = POLLOUT;
                return 1;
        }
        if (test_mode == TEST_SHORT_IO && poll_calls == 1) {
                errno = EINTR;
                return -1;
        }
        return __real_poll(fds, n, timeout);
}

static void send_all(int fd, const char *buffer, size_t size) {
        for (size_t offset = 0; offset < size;) {
                ssize_t n = __real_send(fd, buffer + offset, size - offset, MSG_NOSIGNAL);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        if (errno == EPIPE || errno == ECONNRESET)
                                return;
                }
                CHECK(n > 0);
                offset += (size_t) n;
        }
}

static void run_server(int ready, const char *response, size_t size) {
        sd_json_variant *request = NULL;
        char buffer[65536];
        size_t offset = 0;
        int server, fd;

        if (geteuid() == 0) {
                CHECK(setgid(65534) == 0);
                CHECK(setuid(65534) == 0);
        }
        server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        CHECK(server >= 0);
        CHECK(bind(server, (const struct sockaddr *) &private_address, sizeof(private_address)) == 0);
        CHECK(listen(server, 1) == 0);
        CHECK(write(ready, "1", 1) == 1);

        fd = accept4(server, NULL, NULL, SOCK_CLOEXEC);
        CHECK(fd >= 0);
        close(server);
        if (test_mode == TEST_CLOSED) {
                close(fd);
                CHECK(write(ready, "1", 1) == 1);
                _exit(0);
        }
        close(ready);

        for (;;) {
                ssize_t n;

                CHECK(offset < sizeof(buffer));
                n = read(fd, buffer + offset, sizeof(buffer) - offset);
                if (n < 0 && errno == EINTR)
                        continue;
                CHECK(n >= 0);
                if (n == 0) {
                        CHECK(test_mode == TEST_UNTRUSTED || test_mode == TEST_SHORT_CREDENTIALS ||
                              test_mode == TEST_MISSING_CREDENTIALS);
                        CHECK(offset == 0);
                        close(fd);
                        _exit(0);
                }
                offset += (size_t) n;
                if (buffer[offset - 1] == 0)
                        break;
        }

        CHECK(sd_json_parse(buffer, 0, &request, NULL, NULL) >= 0);
        CHECK(sd_json_variant_is_object(request));
        CHECK(strcmp(sd_json_variant_string(sd_json_variant_by_key(request, "method")),
                     "io.platformd.Trust.EvaluatePolicy") == 0);
        CHECK(sd_json_variant_is_object(sd_json_variant_by_key(request, "parameters")));
        sd_json_variant_unref(request);

        if (test_mode == TEST_DEADLINE) {
                struct timespec delay = { .tv_sec = 2 };

                for (size_t i = 0; i < size; i++) {
                        send_all(fd, response + i, 1);
                        while (nanosleep(&delay, &delay) < 0)
                                CHECK(errno == EINTR);
                        delay = (struct timespec) { .tv_sec = 2 };
                }
        } else
                send_all(fd, response, size);

        close(fd);
        _exit(0);
}

static double monotonic_now(void) {
        struct timespec ts;

        CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
        return (double) ts.tv_sec + (double) ts.tv_nsec / 1000000000.0;
}

static void test_response(TestMode mode, const char *response, size_t size, int expected) {
        sd_json_variant *params = NULL, *reply = NULL;
        char directory[] = "/tmp/platformd-pam-transport.XXXXXX", ready;
        double start, elapsed;
        int pipe_fds[2], status, r;
        pid_t child;

        CHECK(mkdtemp(directory));
        if (geteuid() == 0)
                CHECK(chown(directory, 65534, 65534) == 0);
        CHECK(snprintf(private_address.sun_path, sizeof(private_address.sun_path),
                       "%s/socket", directory) > 0);
        test_mode = mode;
        connect_calls = credential_calls = send_calls = recv_calls = poll_calls = 0;
        CHECK(pipe2(pipe_fds, O_CLOEXEC) == 0);
        child = fork();
        CHECK(child >= 0);
        if (child == 0) {
                close(pipe_fds[0]);
                run_server(pipe_fds[1], response, size);
        }
        close(pipe_fds[1]);
        ready_fd = pipe_fds[0];
        CHECK(read(ready_fd, &ready, 1) == 1);
        CHECK(sd_json_buildo(&params, SD_JSON_BUILD_PAIR("policy", SD_JSON_BUILD_STRING("test-policy"))) >= 0);

        start = monotonic_now();
        r = pam_trust_call("io.platformd.Trust.EvaluatePolicy", params, &reply);
        elapsed = monotonic_now() - start;
        if (r != expected && !(expected == -EBADMSG && r < 0))
                fprintf(stderr, "mode=%d result=%d expected=%d\n", mode, r, expected);
        CHECK(r == expected || (expected == -EBADMSG && r < 0));
        CHECK((r >= 0) == !!reply);
        CHECK(credential_calls == 1);
        if (mode == TEST_UNTRUSTED || mode == TEST_SHORT_CREDENTIALS || mode == TEST_MISSING_CREDENTIALS)
                CHECK(send_calls == 0);
        if (mode == TEST_SHORT_IO)
                CHECK(connect_calls == 2 && send_calls > 3 && recv_calls > 3 && poll_calls > 1);
        if (mode == TEST_DEADLINE) {
                CHECK(elapsed >= 4.5 && elapsed < 6.5);
                CHECK(kill(child, SIGTERM) == 0);
        }

        close(ready_fd);
        CHECK(waitpid(child, &status, 0) == child);
        if (mode == TEST_DEADLINE)
                CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
        else
                CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        CHECK(unlink(private_address.sun_path) == 0);
        CHECK(rmdir(directory) == 0);
        sd_json_variant_unref(params);
        sd_json_variant_unref(reply);
}

static void test_connect_failure(TestMode mode, int expected) {
        sd_json_variant *params = NULL, *reply;

        CHECK(sd_json_buildo(&params, SD_JSON_BUILD_PAIR("policy", SD_JSON_BUILD_STRING("test-policy"))) >= 0);
        test_mode = mode;
        connect_calls = credential_calls = socket_error_calls = send_calls = recv_calls = poll_calls = 0;
        reply = params;
        CHECK(pam_trust_call("io.platformd.Trust.EvaluatePolicy", params, &reply) == expected);
        CHECK(!reply);
        CHECK(connect_calls == 1 && credential_calls == 0 && send_calls == 0 && recv_calls == 0);
        CHECK(socket_error_calls == (unsigned) test_async_failure());
        CHECK(poll_calls == (unsigned) test_async_failure());
        sd_json_variant_unref(params);
}

static void test_invalid_arguments(void) {
        sd_json_variant *params = NULL, *reply;

        CHECK(sd_json_buildo(&params, SD_JSON_BUILD_PAIR("policy", SD_JSON_BUILD_STRING("test-policy"))) >= 0);
        connect_calls = 0;
        reply = params;
        CHECK(pam_trust_call(NULL, params, &reply) == -EINVAL);
        CHECK(!reply);
        reply = params;
        CHECK(pam_trust_call("io.platformd.Trust.EvaluatePolicy", NULL, &reply) == -EINVAL);
        CHECK(!reply);
        CHECK(pam_trust_call("io.platformd.Trust.EvaluatePolicy", params, NULL) == -EINVAL);
        CHECK(connect_calls == 0);
        sd_json_variant_unref(params);
}

int main(void) {
        static const char valid[] = "{\"parameters\":{\"result\":{\"result\":\"policy-satisfied\"}}}";
        static const char trailing[] = "{}\0trailing";
        sd_json_variant *params = NULL, *reply = NULL;
        char *large;

        CHECK(signal(SIGPIPE, SIG_DFL) != SIG_ERR);
        CHECK(setenv("PLATFORMD_TRUST_SOCKET", "/nonexistent/untrusted.sock", 1) == 0);
        CHECK(setenv("PLATFORMD_TRUSTD_RUNTIME", "/nonexistent/untrusted", 1) == 0);

        test_invalid_arguments();
        test_connect_failure(TEST_CONNECT_REFUSED, -ECONNREFUSED);
        test_connect_failure(TEST_ASYNC_REFUSED, -ECONNREFUSED);
        test_connect_failure(TEST_ASYNC_SHORT_ERROR, -EIO);
        test_connect_failure(TEST_ASYNC_MISSING_ERROR, -EIO);
        test_response(TEST_NORMAL, valid, sizeof(valid), 0);
        test_response(TEST_SHORT_IO, valid, sizeof(valid), 0);
        test_response(TEST_UNTRUSTED, valid, sizeof(valid), -EACCES);
        test_response(TEST_SHORT_CREDENTIALS, valid, sizeof(valid), -EACCES);
        test_response(TEST_MISSING_CREDENTIALS, valid, sizeof(valid), -ENOPROTOOPT);
        test_response(TEST_CLOSED, valid, sizeof(valid), -EPIPE);
        test_response(TEST_NORMAL, valid, sizeof(valid) - 1, -EBADMSG);
        test_response(TEST_NORMAL, "{} junk", sizeof("{} junk"), -EBADMSG);
        test_response(TEST_NORMAL, "{}{}", sizeof("{}{}"), -EBADMSG);
        test_response(TEST_NORMAL, "{]", sizeof("{]"), -EBADMSG);
        test_response(TEST_NORMAL, "[]", sizeof("[]"), -EBADMSG);
        test_response(TEST_NORMAL, trailing, sizeof(trailing), -EBADMSG);

        large = malloc(65537);
        CHECK(large);
        memset(large, ' ', 65537);
        memcpy(large, "{}", 2);
        large[65535] = 0;
        test_response(TEST_NORMAL, large, 65536, 0);
        large[65535] = ' ';
        large[65536] = 0;
        test_response(TEST_NORMAL, large, 65537, -E2BIG);

        memset(large, 'x', 65536);
        CHECK(sd_json_buildo(&params, SD_JSON_BUILD_PAIR("padding", SD_JSON_BUILD_STRING(large))) >= 0);
        connect_calls = 0;
        CHECK(pam_trust_call("io.platformd.Trust.EvaluatePolicy", params, &reply) == -E2BIG);
        CHECK(!reply && connect_calls == 0);
        sd_json_variant_unref(params);
        free(large);

        test_response(TEST_DEADLINE, valid, sizeof(valid), -ETIMEDOUT);
        puts("OK: authenticated bounded PAM transport");
        return 0;
}
