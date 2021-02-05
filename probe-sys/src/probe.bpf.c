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

LSM_HOOK(bprm_check_security, execution, struct linux_binprm *bprm) {
  initialize_event();

  // override the process fields since we're execing a new process
  bpf_probe_read_kernel_str(&event->process.executable,
                            sizeof(event->process.executable), bprm->filename);
  event->process.args_count = bprm->argc;

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
