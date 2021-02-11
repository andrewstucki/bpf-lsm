#ifndef __PROBE_H
#define __PROBE_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "probe.generated.h"
#include "probe.skel.h"
#include "probe_macros.h"

struct handle_event_wrapper {
  void *ctx;
  void *handler;
};

DECLARE_HANDLERS(EVENT_HOOKS);
struct handlers {
  DECLARE_HANDLER_WRAPPERS(EVENT_HOOKS);
};

struct state_configuration {
  unsigned char debug;
  DECLARE_HANDLER_CONFIGURATIONS(EVENT_HOOKS);
};

struct state {
  struct probe_bpf *obj;
  struct ring_buffer *rb;
  struct handlers *handlers;
  DECLARE_HOOKS(ALL_HOOKS);
  struct bpf_link *creds_hook;
};

struct state *new_state(struct state_configuration config);
void poll_state(struct state *s, int timeout);
void set_process_path(struct state *s, pid_t pid, const char *file_path);
void destroy_state(struct state *self);

#endif // __PROBE_H
