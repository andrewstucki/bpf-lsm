#ifndef __PROBE_H
#define __PROBE_H

#include <stdint.h>
#include "_probe.h"

#define STATE_ALLOWED 0
#define STATE_DENIED 1

typedef void event_handler(void *ctx, struct event e);

struct state;
struct state *new_state(void *ctx, event_handler *handler,
                        unsigned int filtered_user);
void poll_state(struct state *self, int timeout);
void destroy_state(struct state *self);

#endif /* __PROBE_H */
