/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "worker.h"

#define WORKER_REPLY_MAX (16U * 1024 * 1024)

struct Worker {
        sd_event_source *io, *child, *timer;
        pid_t pid;
        int fd, error;
        char *buffer;
        size_t size, allocated;
        uint64_t deadline;
        WorkerDone done;
        void *userdata;
};

static uint64_t boottime_usec(void) {
        struct timespec ts;

        if (clock_gettime(CLOCK_BOOTTIME, &ts) < 0)
                return UINT64_MAX;
        return (uint64_t) ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

void worker_free(Worker *w) {
        if (!w)
                return;
        sd_event_source_unref(w->io);
        sd_event_source_unref(w->child);
        sd_event_source_unref(w->timer);
        if (w->pid > 0) {
                (void) kill(w->pid, SIGKILL);
                while (waitpid(w->pid, NULL, 0) < 0 && errno == EINTR)
                        ;
        }
        if (w->fd >= 0)
                close(w->fd);
        free(w->buffer);
        free(w);
}

static int worker_read(Worker *w) {
        for (;;) {
                ssize_t n;

                if (w->allocated - w->size < 4096) {
                        size_t allocated = w->allocated + 65536;
                        char *buffer;

                        if (allocated > WORKER_REPLY_MAX)
                                return -E2BIG;
                        buffer = realloc(w->buffer, allocated + 1);
                        if (!buffer)
                                return -ENOMEM;
                        w->buffer = buffer;
                        w->allocated = allocated;
                }
                n = read(w->fd, w->buffer + w->size, w->allocated - w->size);
                if (n < 0 && errno == EINTR)
                        continue;
                if (n < 0)
                        return errno == EAGAIN ? 0 : -errno;
                if (n == 0)
                        return 0;
                w->size += (size_t) n;
                w->buffer[w->size] = 0;
        }
}

static int on_io(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Worker *w = userdata;
        int r = worker_read(w);

        if (r < 0) {
                w->error = r;
                (void) kill(w->pid, SIGKILL);
        }
        if (r < 0 || (revents & (EPOLLHUP | EPOLLERR)))
                w->io = sd_event_source_unref(w->io);
        return 0;
}

static int on_timeout(sd_event_source *source, uint64_t usec, void *userdata) {
        Worker *w = userdata;

        w->error = -ETIMEDOUT;
        (void) kill(w->pid, SIGKILL);
        return 0;
}

static int on_child(sd_event_source *source, const siginfo_t *si, void *userdata) {
        Worker *w = userdata;
        sd_json_variant *reply = NULL, *result = NULL, *error;
        int r;

        w->pid = 0;
        r = worker_read(w);
        if (w->error)
                r = w->error;
        else if (boottime_usec() >= w->deadline)
                r = -ETIMEDOUT;
        else if (si->si_code != CLD_EXITED || si->si_status != EXIT_SUCCESS)
                r = -EIO;
        if (r >= 0 && (!w->buffer || sd_json_parse(w->buffer, 0, &reply, NULL, NULL) < 0))
                r = -EBADMSG;
        if (r >= 0) {
                error = sd_json_variant_by_key(reply, "error");
                result = sd_json_variant_by_key(reply, "result");
                if (!sd_json_variant_is_integer(error) || !result)
                        r = -EBADMSG;
                else
                        r = sd_json_variant_integer(error);
        }
        w->done(r, result, w->userdata);
        sd_json_variant_unref(reply);
        return 0;
}

int worker_start(sd_event *event, uint64_t timeout_usec, WorkerRun run, WorkerDone done,
                 void *userdata, Worker **ret) {
        Worker *w;
        int pair[2], r;
        pid_t parent = getpid();

        if (pipe2(pair, O_CLOEXEC) < 0)
                return -errno;
        w = calloc(1, sizeof *w);
        if (!w) {
                close(pair[0]);
                close(pair[1]);
                return -ENOMEM;
        }
        w->fd = pair[0];
        w->done = done;
        w->userdata = userdata;
        w->deadline = boottime_usec() + timeout_usec;
        w->pid = fork();
        if (w->pid == 0) {
                sd_json_variant *result = NULL, *reply = NULL;
                char *text = NULL;
                size_t size, offset = 0;
                sigset_t signals;

                if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent ||
                    dup2(pair[1], 3) < 0 || fcntl(3, F_SETFD, FD_CLOEXEC) < 0 ||
                    close_range(4, ~0U, 0) < 0)
                        _exit(EXIT_FAILURE);
                sigemptyset(&signals);
                (void) sigprocmask(SIG_SETMASK, &signals, NULL);
                r = run(userdata, &result);
                if (sd_json_buildo(&reply,
                                  SD_JSON_BUILD_PAIR_INTEGER("error", r),
                                  SD_JSON_BUILD_PAIR_VARIANT("result", result)) < 0 ||
                    sd_json_variant_format(reply, 0, &text) < 0)
                        _exit(EXIT_FAILURE);
                size = strlen(text);
                if (size > WORKER_REPLY_MAX)
                        _exit(EXIT_FAILURE);
                while (offset < size) {
                        ssize_t n = write(3, text + offset, size - offset);

                        if (n < 0 && errno == EINTR)
                                continue;
                        if (n <= 0)
                                _exit(EXIT_FAILURE);
                        offset += (size_t) n;
                }
                _exit(EXIT_SUCCESS);
        }
        close(pair[1]);
        if (w->pid < 0) {
                r = -errno;
                goto fail;
        }
        if (fcntl(w->fd, F_SETFL, O_NONBLOCK) < 0) {
                r = -errno;
                goto fail;
        }
        r = sd_event_add_child(event, &w->child, w->pid, WEXITED, on_child, w);
        if (r < 0)
                goto fail;
        r = sd_event_add_io(event, &w->io, w->fd, EPOLLIN, on_io, w);
        if (r < 0)
                goto fail;
        r = sd_event_add_time(event, &w->timer, CLOCK_BOOTTIME, w->deadline, 0, on_timeout, w);
        if (r < 0)
                goto fail;
        *ret = w;
        return 0;
fail:
        worker_free(w);
        return r;
}
