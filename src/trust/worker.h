/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <systemd/sd-event.h>
#include <systemd/sd-json.h>

typedef struct Worker Worker;
typedef int (*WorkerRun)(void *userdata, sd_json_variant **ret);
typedef void (*WorkerDone)(int error, sd_json_variant *result, void *userdata);

int worker_start(sd_event *event, uint64_t timeout_usec, WorkerRun run, WorkerDone done,
                 void *userdata, Worker **ret);
void worker_free(Worker *worker);
