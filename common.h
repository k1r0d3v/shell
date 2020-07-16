#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>


// Terminal bold colors
#define TERM_BRED(x)    "\033[1;31m" x "\033[0m"
#define TERM_BBLUE(x)   "\033[1;34m" x "\033[0m"
#define TERM_BGREEN(x)  "\033[1;32m" x "\033[0m"

/*
#define TERM_BRED(x)    x
#define TERM_BBLUE(x)   x
#define TERM_BGREEN(x)  x
*/

// Large print mode
#define LIST_FLAG_MLPRINT       0x1
// Show special folders flag
#define LIST_FLAG_RECURSIVE     0x2

// Force directories elimination
#define ELIMINATE_FLAG_FORCE    0x1

#define MEMORY_TYPE_MALLOC  0
#define MEMORY_TYPE_MMAP    1
#define MEMORY_TYPE_SHARED  2


struct mmap_record {
    int fd;
    char *filename;
};

struct shared_record {
    key_t key;
};

typedef struct memory_record_t {
    int type;
    void *memory;
    size_t size;
    time_t time;
    union {
        struct mmap_record mr;
        struct shared_record sr;
    };
} memory_record_t;


typedef struct job_record_t
{
    pid_t pid;
    char *cmdline;
    time_t time;

    int priority;
    int status;
    int active;
} job_record_t;

/**
 * @brief Formatted perror, like perror but with format
 *
 * @return Number of characteres write
 */
int perrorf(const char *format, ...);

 /**
 * @brief Concatenates parent and child paths
 *
 * @note This function allocates memory, 
 *       call free when finish to work with the string
 *
 * @param left Left path
 * @param right Right path
 *
 * @return Pointer to the new created string on success else NULL
 */
char *concat_path(const char *left, const char *right, int is_dir) ;

 /**
 * @brief Prints a line with the format of ls -li or ls -lid
 *
 * @param sb File stat struct
 * @return 0 on success else -1
 */
int print_stat_ls(const char *path, const struct stat *sb);

/**
 * @brief Eliminate a file or a directory recursively
 *
 * @param path Path to the file or directory
 * @param flags If path is a folder also delete their contents
 *
 * @return 0 on success else -1
 */
int eliminate_path(const char *path, int flags);

/**
 * @brief Lists a directory recursively
 *
 * @param path The path to list
 * @param max_deep The maximum deep to list, -1 == infinite
 * @param deep The current deep
 * @param flags Print flags, use the macros LIST_FLAG_*
 *
 * @return 0 on success else -1
 */
int list_path(const char *path, int flags);


int create_malloc_record(size_t size, memory_record_t **r);

int create_mmap_record(const char *filename, const char *perms, memory_record_t **r);

int create_shared_key(key_t key, size_t size);

int free_malloc_record(size_t size, memory_record_t *r);

int free_mmap_record(const char *filename, memory_record_t *r);

int free_shared_key(key_t key);

int free_memory_record(void *address);

int free_memory_records();

int map_shared_record(key_t key, memory_record_t **r);

int unmap_shared_record(key_t key, memory_record_t *r);

int print_memory_record(memory_record_t *r);

void print_memory_records(int type);

uintptr_t str2uintptr(const char *s);

intptr_t str2intptr(const char *s);

void hexdump(const void *p, size_t size, int cols, int col_bytes);

void memdump(const void *p, size_t size);

int read_to_mem(const char *filename, void *dst, size_t *size);

int write_from_mem(const char *filename, int append, void *src, size_t size);

int find_executable(const char *path, const char *name);

int create_job_record(pid_t pid, int argc, char **argv);

int clear_job_records();

int print_job_record_by_pid(pid_t pid);

void print_job_records();

#endif
