// clang-format off
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "_probe.h"
// clang-format on

#define RINGBUFFER_FLAGS 0

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

const volatile __u32 filtered_user = 0xffffffff;

//  Security hooks for program execution operations. 

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_hook, struct linux_binprm *bprm)
{
	int ret_val = 0;

	struct _event *e = bpf_ringbuf_reserve(&events, sizeof(struct _event), RINGBUFFER_FLAGS);
	if (!e)
		goto done;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
  __u64 uid_gid = bpf_get_current_uid_gid();

	e->state = 0;
	e->pid = pid_tgid;
	e->tid = pid_tgid >> 32;
  e->gid = uid_gid >> 32;
  e->uid = uid_gid;

	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(current_task, real_parent, pid);

	bpf_get_current_comm(&e->program, sizeof(e->program));
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), bprm->filename);

	if (e->uid == filtered_user) {
		e->state = 1;
		ret_val = -1;
	}

	bpf_ringbuf_submit(e, RINGBUFFER_FLAGS);

done:
	return ret_val;
}

char _license[] SEC("license") = "GPL";
