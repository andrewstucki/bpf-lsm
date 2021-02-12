#ifndef __PROBE_COMMON_H
#define __PROBE_COMMON_H

#ifndef EPERM
#define EPERM 1
#endif

#define RINGBUFFER_FLAGS 0

#define INLINE_STATIC __attribute__((always_inline)) static
#define ARR_LENGTH(x) sizeof(x) / sizeof(x[0])

#ifndef memset
#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(x, y, n) __builtin_memmove((x), (y), (n))
#endif

INLINE_STATIC int ___strncmp(const char *x, const char *y, unsigned int len) {
  const char *a = x;
  const char *b = y;
  for (unsigned int i = 0; i < len; i++) {
    if (!*a && !*b)
      return 0; // we have a null byte at the same location
    if (*a != *b)
      return 1;
    a++;
    b++;
  }
  return 0;
}

#define SET_STRING(x, y) memcpy(x, y, ARR_LENGTH(x))

// rules checks
#define MAX_RULE_SIZE 8
#define TRUE_ABSOLUTE 1
#define FALSE_ABSOLUTE 2
#define EQUAL_OPERATOR 1
#define NOT_EQUAL_OPERATOR 2
#define NUMBER_EQUALITY(x, y) x == y;
#define NUMBER_INEQUALITY(x, y) x != y;
#define STRING_EQUALITY(x, y) ___strncmp(x, y, ARR_LENGTH(x)) == 0
#define STRING_INEQUALITY(x, y) ___strncmp(x, y, ARR_LENGTH(x)) != 0

#define MAX_PATH_SIZE 256
#define MAX_ARGS 64
#define ARGSIZE 128

struct cached_process {
  char name[MAX_PATH_SIZE];
  char executable[MAX_PATH_SIZE];
  char args[MAX_ARGS][ARGSIZE];
  unsigned long args_count;
  int truncated;
};

struct cached_file {
  char path[MAX_PATH_SIZE];
};

#endif // __PROBE_COMMON_H
