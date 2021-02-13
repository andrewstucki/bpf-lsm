#ifndef __MACROS_H
#define __MACROS_H

/*
 * general macros for variadic expansions
 */
#define GET_MACRO(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13,  \
                  NAME, ...)                                                   \
  NAME

#define FE_0(WHAT)
#define FE_1(WHAT, _ctx) WHAT(_ctx)
#define FE_2(WHAT, _ctx, ...) WHAT(_ctx) FE_1(WHAT, __VA_ARGS__)
#define FE_3(WHAT, _ctx, ...) WHAT(_ctx) FE_2(WHAT, __VA_ARGS__)
#define FE_4(WHAT, _ctx, ...) WHAT(_ctx) FE_3(WHAT, __VA_ARGS__)
#define FE_5(WHAT, _ctx, ...) WHAT(_ctx) FE_4(WHAT, __VA_ARGS__)
#define FE_6(WHAT, _ctx, ...) WHAT(_ctx) FE_5(WHAT, __VA_ARGS__)
#define FE_7(WHAT, _ctx, ...) WHAT(_ctx) FE_6(WHAT, __VA_ARGS__)
#define FE_8(WHAT, _ctx, ...) WHAT(_ctx) FE_7(WHAT, __VA_ARGS__)
#define FE_9(WHAT, _ctx, ...) WHAT(_ctx) FE_8(WHAT, __VA_ARGS__)
#define FE_10(WHAT, _ctx, ...) WHAT(_ctx) FE_9(WHAT, __VA_ARGS__)
#define FE_11(WHAT, _ctx, ...) WHAT(_ctx) FE_10(WHAT, __VA_ARGS__)
#define FE_12(WHAT, _ctx, ...) WHAT(_ctx) FE_11(WHAT, __VA_ARGS__)
#define FE_13(WHAT, _ctx, ...) WHAT(_ctx) FE_12(WHAT, __VA_ARGS__)
#define FOR_EACH0(action, ...)                                                 \
  GET_MACRO(_0, __VA_ARGS__, FE_13, FE_12, FE_11, FE_10, FE_9, FE_8, FE_7,     \
            FE_6, FE_5, FE_4, FE_3, FE_2, FE_1, FE_0)                          \
  (action, __VA_ARGS__)

#define FE1_0(WHAT)
#define FE1_1(WHAT, _ctx, _x) WHAT(_ctx, _x)
#define FE1_2(WHAT, _ctx, _x, ...) WHAT(_ctx, _x) FE1_1(WHAT, _ctx, __VA_ARGS__)
#define FE1_3(WHAT, _ctx, _x, ...) WHAT(_ctx, _x) FE1_2(WHAT, _ctx, __VA_ARGS__)
#define FE1_4(WHAT, _ctx, _x, ...) WHAT(_ctx, _x) FE1_3(WHAT, _ctx, __VA_ARGS__)
#define FE1_5(WHAT, _ctx, _x, ...) WHAT(_ctx, _x) FE1_4(WHAT, _ctx, __VA_ARGS__)
#define FE1_6(WHAT, _ctx, _x, ...) WHAT(_ctx, _x) FE1_5(WHAT, _ctx, __VA_ARGS__)
#define FE1_7(WHAT, _ctx, _x, ...) WHAT(_ctx, _x) FE1_6(WHAT, _ctx, __VA_ARGS__)
#define FE1_8(WHAT, _ctx, _x, ...) WHAT(_ctx, _x) FE1_7(WHAT, _ctx, __VA_ARGS__)
#define FE1_9(WHAT, _ctx, _x, ...) WHAT(_ctx, _x) FE1_8(WHAT, _ctx, __VA_ARGS__)
#define FE1_10(WHAT, _ctx, _x, ...)                                            \
  WHAT(_ctx, _x) FE1_9(WHAT, _ctx, __VA_ARGS__)
#define FE1_11(WHAT, _ctx, _x, ...)                                            \
  WHAT(_ctx, _x) FE1_10(WHAT, _ctx, __VA_ARGS__)
#define FE1_12(WHAT, _ctx, _x, ...)                                            \
  WHAT(_ctx, _x) FE1_11(WHAT, _ctx, __VA_ARGS__)
#define FE1_13(WHAT, _ctx, _x, ...)                                            \
  WHAT(_ctx, _x) FE1_12(WHAT, _ctx, __VA_ARGS__)
#define FOR_EACH1(action, _ctx, ...)                                           \
  GET_MACRO(_0, __VA_ARGS__, FE1_13, FE1_12, FE1_11, FE1_10, FE1_9, FE1_8,     \
            FE1_7, FE1_6, FE1_5, FE1_4, FE1_3, FE1_2, FE1_1, FE1_0)            \
  (action, _ctx, __VA_ARGS__)

#define FE2_0(WHAT)
#define FE2_1(WHAT, _ctx, _x, _y) WHAT(_ctx, _x, _y)
#define FE2_2(WHAT, _ctx, _x, _y, ...)                                         \
  WHAT(_ctx, _x, _y) FE2_1(WHAT, _ctx, _x, __VA_ARGS__)
#define FE2_3(WHAT, _ctx, _x, _y, ...)                                         \
  WHAT(_ctx, _x, _y) FE2_2(WHAT, _ctx, _x, __VA_ARGS__)
#define FE2_4(WHAT, _ctx, _x, _y, ...)                                         \
  WHAT(_ctx, _x, _y) FE2_3(WHAT, _ctx, _x, __VA_ARGS__)
#define FE2_5(WHAT, _ctx, _x, _y, ...)                                         \
  WHAT(_ctx, _x, _y) FE2_4(WHAT, _ctx, _x, __VA_ARGS__)
#define FE2_6(WHAT, _ctx, _x, _y, ...)                                         \
  WHAT(_ctx, _x, _y) FE2_5(WHAT, _ctx, _x, __VA_ARGS__)
#define FE2_7(WHAT, _ctx, _x, _y, ...)                                         \
  WHAT(_ctx, _x, _y) FE2_6(WHAT, _ctx, _x, __VA_ARGS__)
#define FE2_8(WHAT, _ctx, _x, _y, ...)                                         \
  WHAT(_ctx, _x, _y) FE2_7(WHAT, _ctx, _x, __VA_ARGS__)
#define FE2_9(WHAT, _ctx, _x, _y, ...)                                         \
  WHAT(_ctx, _x, _y) FE2_8(WHAT, _ctx, _x, __VA_ARGS__)
#define FE2_10(WHAT, _ctx, _x, _y, ...)                                        \
  WHAT(_ctx, _x, _y) FE2_9(WHAT, _ctx, _x, __VA_ARGS__)
#define FE2_11(WHAT, _ctx, _x, _y, ...)                                        \
  WHAT(_ctx, _x, _y) FE2_10(WHAT, _ctx, _x, __VA_ARGS__)
#define FE2_12(WHAT, _ctx, _x, _y, ...)                                        \
  WHAT(_ctx, _x, _y) FE2_11(WHAT, _ctx, _x, __VA_ARGS__)
#define FE2_13(WHAT, _ctx, _x, _y, ...)                                        \
  WHAT(_ctx, _x, _y) FE2_12(WHAT, _ctx, _x, __VA_ARGS__)
#define FOR_EACH2(action, _ctx, _x, ...)                                       \
  GET_MACRO(_0, __VA_ARGS__, FE2_13, FE2_12, FE2_11, FE2_10, FE2_9, FE2_8,     \
            FE2_7, FE2_6, FE2_5, FE2_4, FE2_3, FE2_2, FE2_1, FE2_0)            \
  (action, _ctx, _x, __VA_ARGS__)

/*
 * macros for management of bpf program hooks
 */
#define DECLARE_HOOK(name) struct bpf_link *name##_hook;
#define NULL_HOOK(s, name) s->name##_hook = NULL;
#define SET_HANDLER_CONTEXT(s, config, name)                                   \
  if (config.name##_handler) {                                                 \
    s->handlers->name##_handler->ctx = config.name##_ctx;                      \
    s->handlers->name##_handler->handler = config.name##_handler;              \
  }
#define ATTACH_HOOK_OR(s, label, name)                                         \
  s->name##_hook = bpf_program__attach(s->obj->progs.name##_hook);             \
  if (!s->name##_hook) {                                                       \
    goto label;                                                                \
  }
#define DESTROY_HOOK(s, name)                                                  \
  if (s->name##_hook)                                                          \
    bpf_link__destroy(s->name##_hook);
#define DECLARE_HOOKS(...) FOR_EACH0(DECLARE_HOOK, __VA_ARGS__)
#define NULL_HOOKS(s, ...) FOR_EACH1(NULL_HOOK, s, __VA_ARGS__)
#define SET_HANDLER_CONTEXTS(s, config, ...)                                   \
  FOR_EACH2(SET_HANDLER_CONTEXT, s, config, __VA_ARGS__)
#define ATTACH_HOOKS_OR(s, label, ...)                                         \
  FOR_EACH2(ATTACH_HOOK_OR, s, label, __VA_ARGS__)
#define DESTROY_HOOKS(s, ...) FOR_EACH1(DESTROY_HOOK, s, __VA_ARGS__)

/*
 * macros for managing state configuration
 */
#define DECLARE_HANDLER_CONFIGURATION(name)                                    \
  void *name##_ctx;                                                            \
  name##_event_handler *name##_handler;
#define DECLARE_HANDLER_CONFIGURATIONS(...)                                    \
  FOR_EACH0(DECLARE_HANDLER_CONFIGURATION, __VA_ARGS__)

/*
 * macros for management of bpf event handlers
 */
#define DECLARE_HANDLER_WRAPPER(name)                                          \
  struct handle_event_wrapper *name##_handler;
#define DECLARE_HANDLER(name)                                                  \
  typedef void name##_event_handler(void *ctx, struct bpf_##name##_event_t e); \
  static int handle_##name##_event(void *ctx,                                  \
                                   struct bpf_##name##_event_t bpf_data) {     \
    struct handle_event_wrapper *handle = ctx;                                 \
    name##_event_handler *callback = handle->handler;                          \
    callback(handle->ctx, bpf_data);                                           \
    return 0;                                                                  \
  }
#define WRAP_HANDLER_OR(h, label, name)                                        \
  if (!(h->name##_handler = (struct handle_event_wrapper *)malloc(             \
            sizeof(struct handle_event_wrapper))))                             \
    goto label;
#define HANDLER_CASE(name)                                                     \
  case type_##name##_event_t:                                                  \
    return handle_##name##_event(handlers->name##_handler,                     \
                                 event->name##_event_t);
#define DESTROY_HANDLER(h, name)                                               \
  if (h->name##_handler)                                                       \
    free((void *)h->name##_handler);
#define DECLARE_HANDLER_WRAPPERS(...)                                          \
  FOR_EACH0(DECLARE_HANDLER_WRAPPER, __VA_ARGS__)
#define DECLARE_HANDLERS(...) FOR_EACH0(DECLARE_HANDLER, __VA_ARGS__)
#define WRAP_HANDLERS_OR(h, label, ...)                                        \
  FOR_EACH2(WRAP_HANDLER_OR, h, label, __VA_ARGS__)
#define HANDLER_CASES(...) FOR_EACH0(HANDLER_CASE, __VA_ARGS__)
#define DESTROY_HANDLERS(h, ...) FOR_EACH1(DESTROY_HANDLER, h, __VA_ARGS__)

/*
 * macros for managing rule addition
 */
#define DECLARE_RULE_FLUSHER(name)                                             \
  static unsigned int name##_rejections_size = 0;                              \
  static unsigned int name##_filters_size = 0;                                 \
  void flush_##name##_rejection_rule(struct state *s,                          \
                                     struct query_bpf_##name##_event_t rule) { \
    bpf_map_update_elem(bpf_map__fd(s->obj->maps.name##_rejections),           \
                        &name##_rejections_size, &rule, BPF_ANY);              \
    name##_rejections_size++;                                                  \
    unsigned int index = name##_index;                                         \
    bpf_map_update_elem(bpf_map__fd(s->obj->maps.rejection_rule_sizes),        \
                        &index, &name##_rejections_size, BPF_ANY);             \
  }                                                                            \
                                                                               \
  void flush_##name##_filter_rule(struct state *s,                             \
                                  struct query_bpf_##name##_event_t rule) {    \
    bpf_map_update_elem(bpf_map__fd(s->obj->maps.name##_filters),              \
                        &name##_filters_size, &rule, BPF_ANY);                 \
    name##_filters_size++;                                                     \
    unsigned int index = name##_index;                                         \
    bpf_map_update_elem(bpf_map__fd(s->obj->maps.filter_rule_sizes), &index,   \
                        &name##_filters_size, BPF_ANY);                        \
  }
#define DECLARE_RULE_FLUSHERS(...) FOR_EACH0(DECLARE_RULE_FLUSHER, __VA_ARGS__)

#endif // __MACROS_H
