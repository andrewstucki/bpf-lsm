#ifndef ___PROBE_H
#define ___PROBE_H

#define EPERM 1

struct _event {
	__u32 pid;
	__u32 ppid;
	__u32 tid;
	__u32 gid;
	__u32 uid;
	__u8 state;
	char program[256];
	char filename[256];
};

#endif /* ___PROBE_H */
