#ifndef ___PROBE_H
#define ___PROBE_H

// everything that is used in the bpf program
// should be in this header file

#ifndef EPERM
#define EPERM 1
#endif

#define STATE_ALLOWED 0
#define STATE_DENIED 1

struct event {
  unsigned int tid;
  unsigned int pid;
  unsigned int ppid;
  unsigned int gid;
  unsigned int uid;
  unsigned char state;
  char program[256];
  char filename[256];
};

#endif /* ___PROBE_H */
