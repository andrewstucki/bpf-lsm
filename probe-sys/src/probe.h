#ifndef __PROBE_H
#define __PROBE_H

#include <stdint.h>

#define STATE_ALLOWED 0
#define STATE_DENIED 1

struct event {
	uint32_t tid;
	uint32_t pid;
	uint32_t ppid;
	uint32_t gid;
	uint32_t uid;
	uint8_t state;
	char program[256];
	char filename[256];
};

typedef void event_handler(void *ctx, struct event e);

struct state;
struct state * new_state(void *ctx, event_handler *handler, unsigned int filtered_user);
void poll_state(struct state *self, int timeout);
void destroy_state(struct state *self);

#endif /* __PROBE_H */
