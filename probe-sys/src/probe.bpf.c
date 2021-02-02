// clang-format off
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "probe.bpf.h"
// clang-format on

// change this to a bpf_map_lookup_elem to do dynamic
// filtering while the process is running
const volatile unsigned int filtered_user = 0xffffffff;

//  Security hooks for program execution operations.

LSM_HOOK(bprm_check_security, struct linux_binprm *bprm) {
  initialize_event();

  // override the process fields since we're execing a new process
  bpf_probe_read_kernel_str(&event->process.executable, sizeof(event->process.executable), bprm->filename);
  event->process.args_count = bprm->argc;

  // for now we can only sleep in bprm_committed_creds
  // any additional LSM hooks are not sleepable until
  // kernel 5.11, see:
  // https://github.com/torvalds/linux/commit/423f16108c9d832bd96059d5c882c8ef6d76eb96
  // bpf_copy_from_user(&event->process.target.command_line, bprm->mm->arg_start, (bprm->mm->arg_end - bprm->mm->arg_start));
  // 
  // note that when we try and do this we need to make sure we refactor
  // the ring buffer code, otherwise we get "Sleepable programs can only use array and hash maps"
  // one thought is to gather arguments in one hook invocation and then do the actual
  // accept/reject in another
  // 
  // take a look at https://github.com/torvalds/linux/blob/1048ba83fb1c00cd24172e23e8263972f6b5d9ac/fs/exec.c#L1239
  // for more detailed lifecycle implementation
  
  const char denied[] = "execution-denied";
  const char allowed[] = "execution-allowed";
  if (event->user.id == filtered_user) {
    SET_STRING(event->event.action, denied);
    reject(event)
  }
  SET_STRING(event->event.action, allowed);
  accept(event)
}

// take a look at https://github.com/facebookincubator/katran/blob/master/katran/lib/bpf/balancer_kern.c
// for xdp based packet filtering example
