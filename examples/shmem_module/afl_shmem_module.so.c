/*
   american fuzzy lop++ - shared memory module
   -------------------------------------------

   Compile with:

cc -fPIC -shared -I. -O3 afl_shmem_module.so.c -o afl_shmem_module.so -ldl -lrt

 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/shm.h>

#include "../../config.h"

static int     __afl_debug = 0;
static int     __afl_shmem_fd = -1;
static char *  __afl_shmem_filename = NULL;
unsigned char *__afl_fuzz_ptr;
unsigned int * __afl_fuzz_len;

static size_t (*o_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream);
static ssize_t (*o_read)(int fd, void *buf, size_t count);
static FILE *(*o_fopen)(const char *pathname, const char *mode);
static int (*o_open)(const char *pathname, int flags);
static void *(*o_mmap)(void *addr, size_t length, int prot, int flags, int fd,
                       off_t offset);

// int open(const char *__file, int __oflag, ...) __nonnull ((1));

static void __afl_map_shm_fuzz() {

  char *id_str = getenv(SHM_FUZZ_ENV_VAR);

  if (!id_str) {

    fprintf(stderr, "%s env var missing\n", SHM_FUZZ_ENV_VAR);
    exit(1);

  }

#ifdef USEMMAP
  const char *   shm_file_path = id_str;
  int            shm_fd = -1;
  unsigned char *shm_base = NULL;

  /* create the shared memory segment as if it was a file */
  shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
  if (shm_fd == -1) {

    fprintf(stderr, "shm_open() failed for fuzz\n");
    exit(1);

  }

  __afl_fuzz_len =
      (u32 *)o_mmap(0, MAX_FILE + sizeof(int), PROT_READ, MAP_SHARED, shm_fd, 0);

#else
  unsigned int shm_id = atoi(id_str);

  __afl_fuzz_len = (u32 *)shmat(shm_id, NULL, 0);

#endif

  /* Whooooops. */

  if (__afl_fuzz_len == (void *)-1) {

    fprintf(stderr, "Error: could not access fuzzing shared memory\n");
    exit(1);

  }

  __afl_fuzz_ptr = (unsigned char *)(__afl_fuzz_len + sizeof(int));

  if (getenv("AFL_DEBUG"))
    fprintf(stderr, "DEBUG: successfully got fuzzing shared memory\n");

}

__attribute__((constructor(65535))) void afl_shmem_init() {

#ifdef _DEBUG
  __afl_debug = 1;
#else
  if (getenv("AFL_DEBUG")) __afl_debug = 1;
#endif

  if (__afl_debug) fprintf(stderr, "afl_shmem_module DEBUG1\n");

  void *_inject_handle;
  char *fn = getenv("__AFL_SHMEM_FILENAME");
  if (!fn || *fn == 0 || strcmp(fn, "-") == 0)
    __afl_shmem_fd = 0;
  else
    __afl_shmem_filename = strdup(fn);

  if (__afl_debug) fprintf(stderr, "virtual fuzz input is %s\n", __afl_shmem_filename ? __afl_shmem_filename : "stdin");

  if (!(_inject_handle = dlopen("libc.so", RTLD_NOW))) {

    if (!(_inject_handle = dlopen("libc.so.6", RTLD_NOW))) {

      fprintf(stderr, "can not find libc: %s\n", dlerror());
      exit(1);

    }

  }

  o_open = dlsym(_inject_handle, "open");
  o_read = dlsym(_inject_handle, "read");
  o_fopen = dlsym(_inject_handle, "fopen");
  o_fread = dlsym(_inject_handle, "fread");
  o_mmap = dlsym(_inject_handle, "mmap");

  dlclose(_inject_handle);

  __afl_map_shm_fuzz();

  if (!__afl_fuzz_ptr) {

    fprintf(stderr, "could not get shmem\n");
    exit(1);

  }

  if (!o_open || !o_read || !o_fopen || !o_fread || !o_mmap) {

    fprintf(stderr, "could not get dl functions\n");
    exit(1);

  }

  if (__afl_debug)
    fprintf(stderr, "Success: shmem created and function pointers found\n");

}

ssize_t read(int fd, void *buf, size_t count) {

#ifdef _DEBUG
  if (__afl_debug) fprintf(stderr, "read %d == %d?\n", fd, __afl_shmem_fd);
#endif
  if (fd == __afl_shmem_fd) {

    unsigned int len = count < *__afl_fuzz_len ? count : *__afl_fuzz_len;
#ifdef _DEBUG
    if (__afl_debug) fprintf(stderr, "test case for %u/%u\n", count, *__afl_fuzz_len);
#endif
    memcpy(buf, __afl_fuzz_ptr, len);
    return len;

  } else

    return o_read(fd, buf, count);

}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {

#ifdef _DEBUG
  if (__afl_debug)
    fprintf(stderr, "fread %d == %d?\n", fileno(stream), __afl_shmem_fd);
#endif
  if (fileno(stream) == __afl_shmem_fd) {

    size_t len =
        size * nmemb < *__afl_fuzz_len ? size * nmemb : *__afl_fuzz_len;
#ifdef _DEBUG
    if (__afl_debug) fprintf(stderr, "test case for %u/%u\n", size * nmemb, *__afl_fuzz_len);
#endif
    memcpy((char *)ptr, __afl_fuzz_ptr, len);
    return len;

  } else

    return o_fread(ptr, size, nmemb, stream);

}

int open(const char *pathname, int flags) {

  int fd = o_open(pathname, flags);
  if (__afl_shmem_filename && strcmp(pathname, __afl_shmem_filename) == 0) {

#ifdef _DEBUG
    if (__afl_debug) fprintf(stderr, "watching now for fd %d\n", fd);
#endif
    __afl_shmem_fd = fd;

  }

  return fd;

}

FILE *fopen(const char *pathname, const char *mode) {

  FILE *f = fopen(pathname, mode);
  if (__afl_shmem_filename && strcmp(pathname, __afl_shmem_filename) == 0) {

#ifdef _DEBUG
    if (__afl_debug) fprintf(stderr, "watching now for fd %d\n", fileno(f));
#endif
    __afl_shmem_fd = fileno(f);

  }

  return f;

}

void *mmap(void *addr, size_t length, int prot, int flags, int fd,
           off_t offset) {

#ifdef _DEBUG
  if (__afl_debug) fprintf(stderr, "mmap %d == %d?\n", fd, __afl_shmem_fd);
#endif
  if (fd == __afl_shmem_fd) {

#ifdef _DEBUG
    if (__afl_debug)
      fprintf(stderr, "test case len %lu/%u offset %u\n", length,
              *__afl_fuzz_len, offset);
#endif
    void *ptr = mmap(addr, length, prot | PROT_WRITE, flags, fd, offset);
    if (*__afl_fuzz_len > offset) {

      unsigned int len =
          length < *__afl_fuzz_len - offset ? length : *__afl_fuzz_len - offset;
      memcpy((char *)ptr, __afl_fuzz_ptr + offset, len);

    }

    return ptr;

  } else

    return o_mmap(addr, length, prot, flags, fd, offset);

}

