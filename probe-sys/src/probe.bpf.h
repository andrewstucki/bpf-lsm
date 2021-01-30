// Code generated by scripts/generate-structures - DO NOT EDIT.
// to modify, regenerate after modifying templates/probe.bpf.h.j2

#ifndef __PROBE_BPF_H
#define __PROBE_BPF_H

#ifndef EPERM
#define EPERM 1
#endif

#ifdef BPF
#define RINGBUFFER_FLAGS 0
#define LSM_HOOK(module, args...)                                              \
  __attribute__((always_inline)) static int ____##module(                      \
      unsigned long long *ctx, ##args, struct bpf_##module##_event_t *event);  \
  SEC("lsm/" #module)                                                          \
  int BPF_PROG(module##_hook, ##args) {                                        \
    if (module##_enabled == 0) {                                               \
      return 0;                                                                \
    }                                                                          \
    struct bpf_event_t *event = bpf_ringbuf_reserve(                           \
        &events, sizeof(struct bpf_event_t), RINGBUFFER_FLAGS);                \
    if (event)                                                                 \
      event->type = type_##module##_event_t;                                   \
    int __ret = 0;                                                             \
    _Pragma("GCC diagnostic push")                                             \
        _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") if (event)      \
            __ret =                                                            \
                ____##module(___bpf_ctx_cast(args), &event->module##_event_t); \
    _Pragma("GCC diagnostic pop") if (event)                                   \
        bpf_ringbuf_submit(event, RINGBUFFER_FLAGS);                           \
    return __ret;                                                              \
  }                                                                            \
  static int ____##module(unsigned long long *ctx, ##args,                     \
                          struct bpf_##module##_event_t *event)

#define initialize_event()                                                     \
  if (!event)                                                                  \
    return 0;
#define reject(event) return -EPERM;
#define accept(event) return 0;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

const volatile unsigned char bprm_check_security_enabled = 0;
char _license[] SEC("license") = "GPL";
#endif

// begin bprm_check_security

struct bpf_bprm_check_security_event_process_target_t {
  char executable[256];
  unsigned long args_count;
};

struct bpf_bprm_check_security_event_process_t {
  unsigned int pid;
  char entity_id[256];
  char name[256];
  unsigned int ppid;
  unsigned long thread__id;
  struct bpf_bprm_check_security_event_process_target_t target;
};

struct bpf_bprm_check_security_event_user_group_t {
  unsigned int id;
  char name[256];
};

struct bpf_bprm_check_security_event_user_t {
  unsigned int id;
  char name[256];
  struct bpf_bprm_check_security_event_user_group_t group;
};

struct bpf_bprm_check_security_event_t {
  unsigned long __timestamp;
  struct bpf_bprm_check_security_event_process_t process;
  struct bpf_bprm_check_security_event_user_t user;
};

// end bprm_check_security
enum event_type {

  type_bprm_check_security_event_t,

};

struct bpf_event_t {
  enum event_type type;
  union {

    struct bpf_bprm_check_security_event_t bprm_check_security_event_t;
  };
};

#endif /* __PROBE_BPF_H */