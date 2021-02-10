// clang-format off
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "probe.bpf.h"
// clang-format on

//  Security hooks for program execution operations.

#define MAX_ARGS 64
#define ARGSIZE 128

TRACEPOINT(syscalls, sys_enter_execve, struct trace_event_raw_sys_enter *ctx) {
  initialize_event();

  const char *argp;
  const char **args = (const char **)(ctx->args[1]);

#pragma unroll
  for (int i = 0; i < MAX_ARGS; i++) {
    // get the args from userspace since we can't retrieve
    // them in the lsm hook
    bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
    if (!argp)
      goto done;
    bpf_probe_read_user_str(&event->args[i], ARGSIZE, argp);
  }
  /* try to read one more argument to check if there is one */
  bpf_probe_read_user(&argp, sizeof(argp), &args[MAX_ARGS]);
  if (!argp)
    goto done;

  /* pointer to max_args+1 isn't null, asume we have more arguments */
  event->truncated = 1;

done:
  submit(event);
}

__attribute__((always_inline)) int fork_trace(void *ctx) {
  struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
  struct cached_process_path *child = get_cached_process_path(current_task);
  struct cached_process_path *parent = get_cached_process_path(BPF_CORE_READ(current_task, real_parent));
  if (!child && parent) { // we are in the child process
    // update the path of the process
    set_cached_process_path(parent->path);
  }
  return 0;
}

SIMPLE_TRACEPOINT(syscalls, sys_exit_fork, void *ctx) {
  return fork_trace(ctx);
}

SIMPLE_TRACEPOINT(syscalls, sys_exit_vfork, void *ctx) {
  return fork_trace(ctx);
}

SIMPLE_TRACEPOINT(syscalls, sys_exit_clone, void *ctx) {
  return fork_trace(ctx);
}

SIMPLE_TRACEPOINT(syscalls, sys_exit_clone3, void *ctx) {
  return fork_trace(ctx);
}

LSM_HOOK(bprm_check_security, execution, struct linux_binprm *bprm) {
  initialize_event();

  // override the process fields since we're execing a new process
  bpf_probe_read_kernel_str(&event->process.executable,
                            sizeof(event->process.executable), bprm->filename);
  event->process.args_count = bprm->argc;
  set_cached_process_path(event->process.executable);

  struct tp_sys_enter_execve_event *tp_event =
      get_tracepoint_event(sys_enter_execve);
  if (tp_event) {
    // best effort enrichment

#pragma unroll
    for (int i = 0; i < MAX_ARGS && i < event->process.args_count; i++) {
      memcpy(event->process.args[i], tp_event->args[i], ARGSIZE);
    }
    delete_tracepoint_event(sys_enter_execve);
  }

  submit(event);
}
