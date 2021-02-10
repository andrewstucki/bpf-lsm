#ifndef __PROBE_H
#define __PROBE_H

struct state;

#include "probe.generated.h"

struct state *new_state(struct state_configuration config);
void destroy_state(struct state *self);
void poll_state(struct state *s, int timeout);
void set_process_path(struct state *s, pid_t pid, const char *file_path);

#endif // __PROBE_H
