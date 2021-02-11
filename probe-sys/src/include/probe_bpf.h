#ifndef __PROBE_BPF_H
#define __PROBE_BPF_H

// clang-format off
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
// clang-format on

#include "probe_bpf.generated.h"

char _license[] SEC("license") = "GPL";

const volatile unsigned long clock_adjustment = 0;

INLINE_STATIC unsigned long adjust_timestamp(unsigned long timestamp) {
  return (timestamp + clock_adjustment) / 1000000000l;
}

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

const struct cached_process empty_cached_process = {};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t);
  __type(value, struct cached_process);
} processes SEC(".maps");

INLINE_STATIC struct cached_process *
get_or_create_cached_process(struct task_struct *task) {
  pid_t pid = BPF_CORE_READ(task, tgid);
  bpf_map_update_elem(&processes, &pid, &empty_cached_process, BPF_NOEXIST);
  return bpf_map_lookup_elem(&processes, &pid);
}

INLINE_STATIC struct cached_process *
get_cached_process(struct task_struct *task) {
  pid_t pid = BPF_CORE_READ(task, tgid);
  return bpf_map_lookup_elem(&processes, &pid);
}

INLINE_STATIC void update_cached_process(struct task_struct *task,
                                         const struct cached_process *p) {
  pid_t pid = BPF_CORE_READ(task, tgid);
  bpf_map_update_elem(&processes, &pid, p, BPF_ANY);
}

INLINE_STATIC void delete_cached_process(struct task_struct *task) {
  pid_t pid = BPF_CORE_READ(task, tgid);
  bpf_map_delete_elem(&processes, &pid);
}

#define TRACEPOINT(family, module, ctx)                                        \
  SEC("tp/" #family "/" #module)                                               \
  static int module##_hook(ctx)

#define __check_rejection_filter(m, p, e, r)                                   \
  const char denied[] = "" #p "-denied";                                       \
  const char allowed[] = "" #p "-allowed";                                     \
  if (r == 0) { /* don't override what the user has set */                     \
    unsigned int index = m##_index;                                            \
    unsigned int *size = bpf_map_lookup_elem(&rejection_rule_sizes, &index);   \
    if (size && *size > 0) {                                                   \
      if (___check_##m(*size, &m##_rejections, &event->m##_event_t)) {         \
        SET_STRING(e->event.action, denied);                                   \
        r = -EPERM;                                                            \
      }                                                                        \
    }                                                                          \
  }                                                                            \
  if (r == 0)                                                                  \
    SET_STRING(e->event.action, allowed);

#define __basic_process_info_for_task(x, task, ...)                            \
  x.pid = BPF_CORE_READ(task, ##__VA_ARGS__, tgid);                            \
  x.thread__id = BPF_CORE_READ(task, ##__VA_ARGS__, pid);                      \
  x.ppid = BPF_CORE_READ(task, ##__VA_ARGS__, tgid);                           \
  x.start = adjust_timestamp(BPF_CORE_READ(task, ##__VA_ARGS__, start_time))

#define __copy_cached_process(x, cached)                                       \
  x.args_count = cached->args_count;                                           \
  memcpy(x.executable, cached->executable, MAX_PATH_SIZE);                     \
  memcpy(x.name, cached->name, MAX_PATH_SIZE);                                 \
  _Pragma("unroll") for (int i = 0; i < MAX_ARGS && i < cached->args_count;    \
                         i++) memcpy(x.args[i], cached->args[i], ARGSIZE)

#define LSM_HOOK(module, prefix, ...)                                          \
  INLINE_STATIC int ____##module(unsigned long long *ctx, ##__VA_ARGS__,       \
                                 struct bpf_##module##_event_t *event,         \
                                 struct task_struct *current_task);            \
  SEC("lsm/" #module)                                                          \
  int BPF_PROG(module##_hook, ##__VA_ARGS__) {                                 \
    int __ret = 0;                                                             \
    struct bpf_event_t *event = bpf_ringbuf_reserve(                           \
        &events, sizeof(struct bpf_event_t), RINGBUFFER_FLAGS);                \
    if (event) {                                                               \
      event->type = type_##module##_event_t;                                   \
      struct bpf_##module##_event_t *e = &event->module##_event_t;             \
      struct task_struct *c = (struct task_struct *)bpf_get_current_task();    \
      struct cached_process *cached;                                           \
                                                                               \
      e->__timestamp = adjust_timestamp(bpf_ktime_get_boot_ns());              \
      e->user.id = BPF_CORE_READ(c, real_cred, uid.val);                       \
      e->user.group.id = BPF_CORE_READ(c, real_cred, gid.val);                 \
      e->user.effective.id = BPF_CORE_READ(c, cred, uid.val);                  \
      e->user.effective.group.id = BPF_CORE_READ(c, cred, gid.val);            \
                                                                               \
      __basic_process_info_for_task(e->process, c);                            \
      if ((cached = get_cached_process(c))) {                                  \
        __copy_cached_process(e->process, cached);                             \
      }                                                                        \
                                                                               \
      __basic_process_info_for_task(e->process.parent, c, real_parent);        \
      if ((cached = get_cached_process(BPF_CORE_READ(c, real_parent)))) {      \
        __copy_cached_process(e->process.parent, cached);                      \
      }                                                                        \
                                                                               \
      __ret = ____##module(___bpf_ctx_cast(ARGS), e, c);                       \
      __check_rejection_filter(module, prefix, e, __ret);                      \
      bpf_ringbuf_submit(event, RINGBUFFER_FLAGS);                             \
    }                                                                          \
    return __ret;                                                              \
  }                                                                            \
  static int ____##module(unsigned long long *ctx, ##__VA_ARGS__,              \
                          struct bpf_##module##_event_t *event,                \
                          struct task_struct *current_task)

#define COMPLETE_LSM_HOOK(module, prefix, ...)                                 \
  LSM_HOOK(module, prefix, ##__VA_ARGS__) { return 0; }

// call this at the beginning of a hook to make the verifier happy
#define initialize_event()                                                     \
  if (!event)                                                                  \
    return 0;
    
INLINE_STATIC int __last_index_of(const char *x, const char y, size_t len) {
  const char *a = x;
  int current_index = -1;
#pragma unroll
  for (int i = 0; i < len; i++) {
    if (!*a)
      return current_index; // return whatever our current is at the end of the
                            // string
    if (*a == y)
      current_index = i;
    a++;
  }
  return current_index;
}

INLINE_STATIC void set_basename(char *x, const char *y, size_t len) {
  int last_slash = __last_index_of(y, '/', len) % len;
  if (last_slash < 0)
    return;
  last_slash++;
  size_t end = len - last_slash;
#pragma unroll
  for (size_t i = 0; i < len && i < end; i++) {
    x[i] = y[i + last_slash];
  }
}

#endif // __PROBE_BPF_H
