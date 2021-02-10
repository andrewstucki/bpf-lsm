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

__attribute__((always_inline)) static unsigned long
adjust_timestamp(unsigned long timestamp) {
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

#define get_or_create_cached_process(task)                                          \
  (struct cached_process *)__get_or_create_cached_process(task)
__attribute__((always_inline)) static void *
__get_or_create_cached_process(struct task_struct *task) {
  pid_t pid = BPF_CORE_READ(task, tgid);
  bpf_map_update_elem(&processes, &pid, &empty_cached_process, BPF_NOEXIST);
  return bpf_map_lookup_elem(&processes, &pid);
}

#define get_cached_process(task)                                          \
  (struct cached_process *)__get_cached_process(task)
__attribute__((always_inline)) static void *
__get_cached_process(struct task_struct *task) {
  pid_t pid = BPF_CORE_READ(task, tgid);
  return bpf_map_lookup_elem(&processes, &pid);
}

#define update_cached_process(task, process)                                          \
  __update_cached_process(task, process)
__attribute__((always_inline)) static void
__update_cached_process(struct task_struct *task, const struct cached_process *process) {
  pid_t pid = BPF_CORE_READ(task, tgid);
  bpf_map_update_elem(&processes, &pid, process, BPF_ANY);
}

#define delete_cached_process(task)                                          \
  __delete_cached_process(task)
__attribute__((always_inline)) static void
__delete_cached_process(struct task_struct *task) {
  pid_t pid = BPF_CORE_READ(task, tgid);
  bpf_map_delete_elem(&processes, &pid);
}

#define TRACEPOINT(family, module, arg)                                        \
  __attribute__((always_inline)) static int ____##module(arg);                 \
  SEC("tp/" #family "/" #module)                                               \
  int module##_hook(void *ctx) { return ____##module(ctx); }                   \
  static int ____##module(arg)

#define LSM_HOOK(module, prefix, args...)                                      \
  __attribute__((always_inline)) static int ____##module(                      \
      unsigned long long *ctx, ##args, struct bpf_##module##_event_t *event,   \
      struct task_struct *current_task);                                       \
  SEC("lsm/" #module)                                                          \
  int BPF_PROG(module##_hook, ##args) {                                        \
    struct bpf_event_t *event = bpf_ringbuf_reserve(                           \
        &events, sizeof(struct bpf_event_t), RINGBUFFER_FLAGS);                \
    if (event)                                                                 \
      event->type = type_##module##_event_t;                                   \
    int __ret = 0;                                                             \
    if (event) {                                                               \
      struct task_struct *current_task =                                       \
          (struct task_struct *)bpf_get_current_task();                        \
                                                                               \
      event->module##_event_t.__timestamp =                                    \
          adjust_timestamp(bpf_ktime_get_boot_ns());                           \
                                                                               \
      event->module##_event_t.process.pid = BPF_CORE_READ(current_task, tgid); \
      event->module##_event_t.process.thread__id =                             \
          BPF_CORE_READ(current_task, pid);                                    \
      event->module##_event_t.process.ppid =                                   \
          BPF_CORE_READ(current_task, real_parent, tgid);                      \
      event->module##_event_t.process.start =                                  \
          adjust_timestamp(BPF_CORE_READ(current_task, start_time));           \
      BPF_CORE_READ_INTO(&event->module##_event_t.process.name, current_task,  \
                         comm);                                                \
                                                                               \
      event->module##_event_t.process.parent.pid =                             \
          BPF_CORE_READ(current_task, real_parent, tgid);                      \
      event->module##_event_t.process.parent.thread__id =                      \
          BPF_CORE_READ(current_task, real_parent, pid);                       \
      event->module##_event_t.process.parent.ppid =                            \
          BPF_CORE_READ(current_task, real_parent, real_parent, tgid);         \
      event->module##_event_t.process.parent.start = adjust_timestamp(         \
          BPF_CORE_READ(current_task, real_parent, start_time));               \
      BPF_CORE_READ_INTO(&event->module##_event_t.process.parent.name,         \
                         current_task, real_parent, comm);                     \
                                                                               \
      event->module##_event_t.user.id =                                        \
          BPF_CORE_READ(current_task, real_cred, uid.val);                     \
      event->module##_event_t.user.group.id =                                  \
          BPF_CORE_READ(current_task, real_cred, gid.val);                     \
      event->module##_event_t.user.effective.id =                              \
          BPF_CORE_READ(current_task, cred, uid.val);                          \
      event->module##_event_t.user.effective.group.id =                        \
          BPF_CORE_READ(current_task, cred, gid.val);                          \
                                                                               \
      struct cached_process *cached =                                \
          get_cached_process(current_task);                               \
      if (cached) {                                                       \
        memcpy(event->module##_event_t.process.executable, cached->executable,  \
               MAX_PATH_SIZE);                                                 \
      }                                                                        \
      cached =                                                            \
          get_cached_process(BPF_CORE_READ(current_task, real_parent));   \
      if (cached) {                                                       \
        memcpy(event->module##_event_t.process.parent.executable,              \
               cached->executable, MAX_PATH_SIZE);                              \
      }                                                                        \
                                                                               \
      __ret = ____##module(___bpf_ctx_cast(args), &event->module##_event_t,    \
                           current_task);                                      \
      const char denied[] = "" #prefix "-denied";                              \
      const char allowed[] = "" #prefix "-allowed";                            \
      if (__ret == 0) { /* don't override what the user has set */             \
        unsigned int index = module##_index;                                   \
        unsigned int *size =                                                   \
            bpf_map_lookup_elem(&rejection_rule_sizes, &index);                \
        if (size && *size > 0) {                                               \
          if (___check_##module(*size, &module##_rejections,                   \
                                &event->module##_event_t)) {                   \
            SET_STRING(event->module##_event_t.event.action, denied);          \
            __ret = -EPERM;                                                    \
          } else {                                                             \
            SET_STRING(event->module##_event_t.event.action, allowed);         \
          }                                                                    \
        } else {                                                               \
          SET_STRING(event->module##_event_t.event.action, allowed);           \
        }                                                                      \
      } else {                                                                 \
        SET_STRING(event->module##_event_t.event.action, allowed);             \
      }                                                                        \
    }                                                                          \
    if (event)                                                                 \
      bpf_ringbuf_submit(event, RINGBUFFER_FLAGS);                             \
    return __ret;                                                              \
  }                                                                            \
  static int ____##module(unsigned long long *ctx, ##args,                     \
                          struct bpf_##module##_event_t *event,                \
                          struct task_struct *current_task)

#define initialize_event()                                                     \
  if (!event)                                                                  \
    return 0;
#define submit(event) return 0

#endif // __PROBE_BPF_H
