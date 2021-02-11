#include "probe.h"

static int handle_event(void *ctx, void *data, unsigned long size) {
  struct bpf_event_t *event = data;
  struct handlers *handlers = ctx;
  switch (event->type) { HANDLER_CASES(EVENT_HOOKS); }
  return 0;
}

int print_libbpf_log(enum libbpf_print_level lvl, const char *fmt,
                     va_list args) {
  return vfprintf(stderr, fmt, args);
}

int noop_log(enum libbpf_print_level lvl, const char *fmt, va_list args) {
  return 0;
}

INLINE_STATIC unsigned long get_clock_offset() {
  unsigned long clock_adjustment;
  struct timespec boot;
  struct timespec current;
  clock_gettime(CLOCK_BOOTTIME, &boot);
  clock_gettime(CLOCK_REALTIME, &current);
  unsigned long current_ns = 1000000000 * current.tv_sec + current.tv_nsec;
  unsigned long boot_ns = 1000000000 * boot.tv_sec + boot.tv_nsec;
  return current_ns - boot_ns;
}

INLINE_STATIC void destroy_handlers(struct handlers *h) {
  if (h) {
    DESTROY_HANDLERS(h, EVENT_HOOKS);
    free((void *)h);
  }
  h = NULL;
}

INLINE_STATIC struct handlers *new_handlers() {
  struct handlers *h = (struct handlers *)malloc(sizeof(struct handlers));
  if (!h) {
    goto cleanup;
  }
  WRAP_HANDLERS_OR(h, cleanup, EVENT_HOOKS);

  goto done;

cleanup:
  destroy_handlers(h);

done:
  return h;
}

struct state *new_state(struct state_configuration config) {
  if (config.debug) {
    libbpf_set_print(print_libbpf_log);
  } else {
    libbpf_set_print(noop_log);
  }
  struct state *s = (struct state *)malloc(sizeof(struct state));
  if (!s) {
    goto cleanup;
  }
  s->handlers = new_handlers();
  if (!s->handlers) {
    goto cleanup;
  }
  s->obj = NULL;

  NULL_HOOKS(s, ALL_HOOKS);
  s->obj = probe_bpf__open();
  if (!s->obj) {
    goto cleanup;
  }
  s->obj->rodata->clock_adjustment = get_clock_offset();

  SET_HANDLER_CONTEXTS(s, config, EVENT_HOOKS)

  if (probe_bpf__load(s->obj)) {
    goto cleanup;
  }

  s->rb = ring_buffer__new(bpf_map__fd(s->obj->maps.events), handle_event,
                           (void *)s->handlers, NULL);
  if (!s->rb) {
    goto cleanup;
  }

  ATTACH_HOOKS_OR(s, cleanup, ALL_HOOKS);

  goto done;

cleanup:
  destroy_state(s);
  s = NULL;

done:
  return s;
}

void poll_state(struct state *s, int timeout) {
  if (s->rb) {
    ring_buffer__poll(s->rb, timeout);
  }
}

void cache_process(struct state *s, pid_t pid, const struct cached_process *process) {
  // this copies the data at the pointer into the kernel
  bpf_map_update_elem(bpf_map__fd(s->obj->maps.processes), &pid, process,
                      BPF_ANY);
}

DECLARE_RULE_FLUSHERS(EVENT_HOOKS);

void destroy_state(struct state *s) {
  if (s) {
    if (s->rb) {
      ring_buffer__free(s->rb);
    }
    DESTROY_HOOKS(s, ALL_HOOKS);
    if (s->obj) {
      probe_bpf__destroy(s->obj);
    }
    if (s->handlers) {
      destroy_handlers(s->handlers);
    }
    free((void *)s);
  }
  s = NULL;
}
