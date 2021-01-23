#include "probe.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "_probe.h"
#include "probe.skel.h"

struct handle_event_wrapper {
  void *ctx;
  event_handler *handler;
};

struct state {
  struct probe_bpf *obj;
  struct ring_buffer *rb;
  struct bpf_link *hook;
  struct handle_event_wrapper *handler;
};

int print_libbpf_log(enum libbpf_print_level lvl, const char *fmt,
                     va_list args) {
  return vfprintf(stderr, fmt, args);
}

static inline int handle_event(void *ctx, void *data, unsigned long size) {
  struct _event *e = data;
  struct handle_event_wrapper *handle = ctx;
  struct event ev = {
      .tid = e->tid,
      .pid = e->pid,
      .ppid = e->ppid,
      .gid = e->gid,
      .uid = e->uid,
      .state = e->state,
  };
  memcpy(ev.filename, e->filename, sizeof(ev.filename));
  memcpy(ev.program, e->program, sizeof(ev.program));
  handle->handler(handle->ctx, ev);
  return 0;
}

struct state *new_state(void *ctx, event_handler *handler,
                        unsigned int filtered_uid) {
  libbpf_set_print(print_libbpf_log);
  struct state *s = (struct state *)malloc(sizeof(struct state));
  if (!s) {
    return NULL;
  }
  s->handler = (struct handle_event_wrapper *)malloc(
      sizeof(struct handle_event_wrapper));
  if (!s->handler) {
    goto cleanup_state;
  }
  s->handler->ctx = ctx;
  s->handler->handler = handler;

  s->obj = probe_bpf__open();
  if (!s->obj) {
    goto cleanup_handler;
  }
  s->obj->rodata->filtered_user = filtered_uid;

  if (probe_bpf__load(s->obj)) {
    goto cleanup_bpf;
  }

  int ringbuffer_fd = bpf_map__fd(s->obj->maps.events);
  if (ringbuffer_fd < 0) {
    goto cleanup_bpf;
  }
  s->rb =
      ring_buffer__new(ringbuffer_fd, handle_event, (void *)s->handler, NULL);
  if (!s->rb) {
    goto cleanup_bpf;
  }
  s->hook = bpf_program__attach_lsm(s->obj->progs.lsm_hook);
  if (!s->hook) {
    goto cleanup_buffer;
  }

  goto done;

cleanup_buffer:
  ring_buffer__free(s->rb);
cleanup_bpf:
  probe_bpf__destroy(s->obj);
cleanup_handler:
  free((void *)s->handler);
cleanup_state:
  free((void *)s);
  s = NULL;

done:
  return s;
}

void destroy_state(struct state *s) {
  if (s != NULL) {
    if (s->rb != NULL) {
      ring_buffer__free(s->rb);
    }
    if (s->hook != NULL) {
      bpf_link__destroy(s->hook);
    }
    if (s->obj != NULL) {
      probe_bpf__destroy(s->obj);
    }
    if (s->handler != NULL) {
      free((void *)s->handler);
    }
    free((void *)s);
  }
}

void poll_state(struct state *s, int timeout) {
  ring_buffer__poll(s->rb, timeout);
}
