// clang-format off
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "probe.bpf.h"
// clang-format on

const volatile unsigned int filtered_user = 0xffffffff;

//  Security hooks for program execution operations.

LSM_HOOK(bprm_check_security, struct linux_binprm *bprm) {
  initialize_event();

  unsigned long pid_tgid = bpf_get_current_pid_tgid();
  unsigned long uid_gid = bpf_get_current_uid_gid();
  struct task_struct *current_task =
      (struct task_struct *)bpf_get_current_task();

  event->process.pid = pid_tgid;
  event->process.thread__id = pid_tgid >> 32;
  event->process.ppid = BPF_CORE_READ(current_task, real_parent, pid);
  bpf_get_current_comm(&event->process.name, sizeof(event->process.name));
  bpf_probe_read_kernel_str(&event->process.target.executable, sizeof(event->process.target.executable), bprm->filename);

  event->user.group.id = uid_gid >> 32;
  event->user.id = uid_gid;

  bpf_printk("User id: %d, Group id: %d\n", event->user.id, event->user.group.id);
  if (event->user.id == filtered_user) {
    reject(event)
  }

  accept(event)
}
