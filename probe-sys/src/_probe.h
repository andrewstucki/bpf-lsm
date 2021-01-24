#ifndef ___PROBE_H
#define ___PROBE_H

#ifndef EPERM
#define EPERM 1
#endif

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
