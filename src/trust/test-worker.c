/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#include "worker.h"

typedef struct Test {
        Worker *worker;
        unsigned delay;
        bool finished;
        int error;
} Test;

static int run(void *userdata, sd_json_variant **ret) {
        Test *t = userdata;

        usleep(t->delay);
        return sd_json_buildo(ret, SD_JSON_BUILD_PAIR_BOOLEAN("done", true));
}

static void done(int error, sd_json_variant *result, void *userdata) {
        Test *t = userdata;

        t->error = error;
        if (error >= 0)
                assert(sd_json_variant_boolean(sd_json_variant_by_key(result, "done")));
        t->finished = true;
        worker_free(t->worker);
        t->worker = NULL;
}

int main(void) {
        sd_event *event = NULL;
        sigset_t signals;
        Test fast = {}, slow = { .delay = 500000 }, expired = {};

        sigemptyset(&signals);
        sigaddset(&signals, SIGCHLD);
        assert(sigprocmask(SIG_BLOCK, &signals, NULL) == 0);
        assert(sd_event_new(&event) >= 0);
        assert(worker_start(event, 100000, run, done, &slow, &slow.worker) >= 0);
        assert(worker_start(event, 100000, run, done, &fast, &fast.worker) >= 0);
        while (!fast.finished)
                assert(sd_event_run(event, 1000000) >= 0);
        assert(fast.error == 0);
        assert(!slow.finished);
        while (!slow.finished)
                assert(sd_event_run(event, 1000000) >= 0);
        assert(slow.error == -ETIMEDOUT);

        assert(worker_start(event, 100000, run, done, &expired, &expired.worker) >= 0);
        usleep(200000);
        while (!expired.finished)
                assert(sd_event_run(event, 1000000) >= 0);
        assert(expired.error == -ETIMEDOUT);
        assert(worker_start(event, 1000000, run, done, &slow, &slow.worker) >= 0);
        worker_free(slow.worker);
        sd_event_unref(event);
        return 0;
}
