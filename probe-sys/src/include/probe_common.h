#ifndef __PROBE_COMMON_H
#define __PROBE_COMMON_H

#ifndef EPERM
#define EPERM 1
#endif

#define RINGBUFFER_FLAGS 0

#ifndef memset
#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

__attribute__((always_inline)) static int
___strncmp(const char *x, const char *y, unsigned int len) {
  const char *a = x;
  const char *b = y;
#pragma unroll
  for (unsigned int i = 0; i < len; i++) {
    if (!*a && !*b)
      return 0; // we have a null byte at the same location
    if (*a != *b)
      return 1;
    a += 1;
    b += 1;
  }
  return 0;
}

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

#define SET_STRING(dest, src)                                                  \
  memcpy(dest, src, (sizeof(dest) / sizeof(dest[0])))

// rules checks
#define MAX_RULE_SIZE 8
#define TRUE_ABSOLUTE 1
#define FALSE_ABSOLUTE 2
#define EQUAL_OPERATOR 1
#define NOT_EQUAL_OPERATOR 2
#define NUMBER_EQUALITY(first, second) first == second;
#define NUMBER_INEQUALITY(first, second) first != second;
#define STRING_EQUALITY(first, second)                                         \
  ___strncmp(first, second, (sizeof(first) / sizeof(first[0]))) == 0
#define STRING_INEQUALITY(first, second)                                       \
  ___strncmp(first, second, (sizeof(first) / sizeof(first[0]))) != 0

#define MAX_PATH_SIZE 256
#define MAX_ARGS 64
#define ARGSIZE 128

struct cached_process {
  char name[MAX_PATH_SIZE];
  char executable[MAX_PATH_SIZE];
  char args[ARGSIZE][MAX_ARGS];
  unsigned long args_count;
  int truncated;
};

#endif // __PROBE_COMMON_H
