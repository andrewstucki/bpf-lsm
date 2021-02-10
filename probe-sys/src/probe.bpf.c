#include "probe_bpf.h"

//  Security hooks for program execution operations.

__attribute__((always_inline)) int fork_trace(void *ctx) {
  // this is to handle programs which fork multiple times
  // without ever calling exec
  struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
  struct cached_process *child = get_cached_process(current_task);
  struct cached_process *parent = get_cached_process(BPF_CORE_READ(current_task, real_parent));
  if (parent && !child) { // we are in the child process
    // update the current task with the parent information
    update_cached_process(current_task, parent);
  }
  return 0;
}

TRACEPOINT(syscalls, sys_exit_fork, void *ctx) {
  return fork_trace(ctx);
}

TRACEPOINT(syscalls, sys_exit_vfork, void *ctx) {
  return fork_trace(ctx);
}

TRACEPOINT(syscalls, sys_exit_clone, void *ctx) {
  return fork_trace(ctx);
}

TRACEPOINT(syscalls, sys_exit_clone3, void *ctx) {
  return fork_trace(ctx);
}

TRACEPOINT(syscalls, sys_enter_execve, struct trace_event_raw_sys_enter *ctx) {
  struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();

  struct cached_process *cached = get_or_create_cached_process(current_task);
  if (!cached) return 0;
  const char *argp;
  const char **args = (const char **)(ctx->args[1]);
  
#pragma unroll
  for (int i = 0; i < MAX_ARGS; i++) {
    // get the args from userspace since we can't retrieve
    // them in the lsm hook
    bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
    if (!argp)
      goto done;
    bpf_probe_read_user_str(&cached->args[i], ARGSIZE, argp);
  }
  /* try to read one more argument to check if there is one */
  bpf_probe_read_user(&argp, sizeof(argp), &args[MAX_ARGS]);
  if (!argp)
    goto done;

  /* pointer to max_args+1 isn't null, asume we have more arguments */
  cached->truncated = 1;

done:
  return 0;
}

LSM_HOOK(bprm_check_security, execution, struct linux_binprm *bprm) {
  initialize_event();

  // override the process fields since we're execing a new process
  bpf_probe_read_kernel_str(&event->process.executable,
                            sizeof(event->process.executable), bprm->filename);
  event->process.args_count = bprm->argc;
  struct cached_process *cached = get_or_create_cached_process(current_task);
  if (cached) {
    // update with the found executable
    memcpy(cached->executable, event->process.executable, MAX_PATH_SIZE);

    #pragma unroll
    for (int i = 0; i < MAX_ARGS && i < event->process.args_count; i++) {
      memcpy(event->process.args[i], cached->args[i], ARGSIZE);
    }

    update_cached_process(current_task, cached);
  }

  submit(event);
}

TRACEPOINT(sched, sched_process_free, void *ctx) {
  struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
  delete_cached_process(current_task);
  return 0;
}
