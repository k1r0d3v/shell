#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <limits.h>
#include <inttypes.h>
#include <errno.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "common.h"
#include "list.h"

#define MAX_CMD_LENGTH  2048
#define STRTOK_DELIM    " \t\n"

#define READ_ERROR      (-1)
#define READ_SUCCESS    0

#define PARSE_UNKNOWN   (-2)
#define PARSE_ERROR     (-1)
#define PARSE_SUCCESS   0
#define PARSE_EXIT      1

#define parse_uintptr_or_return_error(x) str2uintptr((x));\
    if (errno == ERANGE || errno == EINVAL) {\
        printf("str2uintptr: bad number format.\n");\
        return PARSE_ERROR;\
}

#define parse_intptr_or_return_error(x) str2intptr((x));\
    if (errno == ERANGE || errno == EINVAL) {\
        printf("str2uintptr: bad number format.\n");\
        return PARSE_ERROR;\
}

struct parse_command_entry {
    char *name;
    int (*parse)(int argc, char **argv);    
};

/**
 * @brief Splits a command line into command line format
 * @param line Text command line
 * @param argc Output argument count
 * @param args Output arguments
 * @param count Maximum number of aguments to split
 */
void split_line(char *line, int *argc, char *args[], size_t count)
{
    char *token;

    if (count < 1 || args == NULL || argc == NULL || line == NULL) 
        return;

    memset(args, 0, sizeof(char*) * count);

    token = strtok(line, STRTOK_DELIM);

    args[0] = token;

    if (token == NULL) {
        *argc = 0;
        return;
    }

    *argc = 1;

    while (*argc < count && (token = strtok(NULL, STRTOK_DELIM))) {
        args[*argc] = token;
        (*argc)++;
    }
}

/** 
 * @brief Parse a command line
 *
 * @note The last entry of cmds must be NULL, NULL
 * 
 * @param line The line to parse
 * @return If command is found, returns command parse method else PARSE_ERROR
 */
int parse_line(int argc, char **argv, 
                struct parse_command_entry *cmds, 
                struct parse_command_entry *unk)
{    
    int result = PARSE_ERROR;

    if (argc == 0)
        return result;

    // Search for a known command int cmds    
    for (; cmds->name; cmds++) 
    {
        if (!strcmp(argv[0], cmds->name)) 
        {
            if (cmds->parse)
                result = cmds->parse(argc, argv);
            else 
                printf("%s: command not implemented\n", argv[0]);

            break;
        }
    }
    
    if (!cmds->name)
    {
        result = unk->parse(argc, argv);
        if (result == PARSE_UNKNOWN) {
            printf("%s: command not found\n", argv[0]);
            result = PARSE_ERROR;
        }
    }
    return result;
}

/** 
 * @brief Prints the promt
 *
 * @return Number of characters write to stdout else on error -1
 */
int print_prompt()
{
    struct passwd *pwd;
    pwd = getpwuid(geteuid());

    if (pwd == NULL) {
        perror(TERM_BRED("Error")": Cannot get the effective user name\n");
        return -1;
    }

    char host_name[HOST_NAME_MAX + 1];
    memset(host_name, 0, sizeof(char) * (HOST_NAME_MAX + 1));

    if (gethostname(host_name, HOST_NAME_MAX + 1) < 0) {
        perror(TERM_BRED("Error")": Cannot get the host name\n");
        return -1;
    }

    char cwd[PATH_MAX];
    memset(cwd, 0, sizeof(char) * PATH_MAX);
    if (getcwd(cwd, PATH_MAX) == NULL) {
        perror(TERM_BRED("Error")": Cannot get the current working directory\n");
        return -1;
    }

    printf(TERM_BGREEN("%s@%s")":"TERM_BBLUE("%s")"$ ", pwd->pw_name, host_name, cwd);
    fflush(stdout);
    return 0;
}

/** 
 * @brief Prints pid command usage
 */
void print_pid_usage()
{
    fprintf(stdout,
            "Usage: pid [options]\n"
            "Print the process id\n\n"
            "Options:\n"
            "  -p                      print parent pid\n\n");
}

/** 
 * @brief Prints authors command usage
 */
void print_authors_usage()
{
    fprintf(stdout,
            "Usage: autores [options]\n"
            "Print the login and name of the authors.\n\n"
            "Options:\n"
            "  -l                      print only the authors login\n"
            "  -n                      print only the authors name\n\n");
}

/** 
 * @brief Prints info command usage
 */
void print_info_usage()
{
    fprintf(stdout,
            "Usage: info name1 [name2, ...]\n"
            "Print the name information in the same format that \"ls -li\".\n\n");
}

/** 
 * @brief Prints recursive command usage
 */
void print_recursive_usage()
{
    fprintf(stdout,
        "Usage: recursive [ON|OFF]\n"
        "Sets or print the variable recursive.\n"
        "If argument is not given prints the current value\n\n"
        "Options:\n"
        "  ON                      enables recursive on list\n"
        "  OFF                     disables recursive on list\n\n");
}

/** 
 * @brief Prints list command usage
 */
void print_list_usage()
{
    fprintf(stdout,
        "Usage: list [-l] [name, ...]\n"
        "List directories and files.\n\n"
        "If recursive flag is set also travel through the subdirectories\n\n"
        "Options:\n"
        "  -l                      enables long listing, like info command\n\n");
}

/** 
 * @brief Prints eliminate command usage
 */
void print_eliminate_usage()
{
    fprintf(stdout,
        "Usage: eliminate [-f] name\n"
        "Deletes a file or directory.\n\n"         
        "Options:\n"
        "  -f                      deletes a directory although it is empty\n\n");
}

void print_malloc_usage()
{
    fprintf(stdout,
        "Usage: malloc [-deallocate] [size]\n"
        "Allocates memory with the specified size, if no size is given"
        " prints made allocations.\n\n"
        "Options:\n"
        "  size                      Size to allocate\n\n");
}

void print_deallocate_usage()
{
    fprintf(stdout,
        "Usage: deallocate address\n"
        "address supports decimal, hexadecimal(0x), octal(0o) and binary(0b) representations\n"
        "Deallocates the memory pointed by address.\n\n");
}

void print_memdump_usage()
{
    fprintf(stdout,
        "Usage: memdump address [size]\n"
        "Dumps size bytes memory pointed by address, if size is not given by default will dump 25 bytes.\n\n");
}

void print_recursivefunction_usage()
{
    fprintf(stdout,
        "Usage: recursivefunction count\n"
        "Calls a recursive function count times + 1.\n\n");
}

void print_rmkey_usage()
{
    fprintf(stdout,
        "Usage: rmkey key\n"
        "Removes the shared memory with associated key.\nThis command not unmaps the shared memory.\n\n");
}

// TODO: void print_setpriority_usage() { "setpriority [pid] [value]" };

/** 
 * @brief Parse pid command options
 *
 * @return PARSE_SUCCESS if no error else PARSE_ERROR
 */
int parse_pid(int argc, char **argv)
{
    pid_t pid;
    int result = PARSE_SUCCESS;

    if (argv[1] == NULL) {
        pid = getpid();
        printf("%d\n", pid);
    } else if (!strcmp(argv[1], "-p")) {
        pid = getppid();
        printf("%d\n", pid);
    } else {
        printf("pid: invalid option \"%s\"\n", argv[1]);
        result = PARSE_ERROR;

        print_pid_usage();
    }

    return result;
}

/** 
 * @brief Parse authors command options
 *
 * @return PARSE_SUCCESS if no error else PARSE_ERROR
 */
int parse_authors(int argc, char **argv)
{
    int result = PARSE_SUCCESS;

    if (argv[1] == NULL) {
        printf("Alejandro Romero Rivera | alejandro.romero.rivera\n");
    } else if (!strcmp(argv[1], "-l")) {
        printf("alejandro.romero.rivera\n");
    } else if (!strcmp(argv[1], "-n")) {
        printf("Alejandro Romero Rivera\n");
    } else {
        printf("autores: invalid option \"%s\"\n", argv[1]);
        result = PARSE_ERROR;

        print_authors_usage();
    }

    return result;
}

/** 
 * @brief Parse exit command
 *
 * @return PARSE_EXIT
 */
int parse_exit(int argc, char **argv)
{
    if (argv[1] != NULL)
        printf("exit: invalid option \"%s\"\n", argv[1]);

    return PARSE_EXIT;
}

/**
 * @brief Parse info command
 *
 * @return PARSE_SUCCESS on succes else PARSE_ERROR
 */
int parse_info(int argc, char **argv)
{
    int i;
    struct stat sb;

    if (argv[1] == NULL) {
        print_info_usage();
        return PARSE_ERROR;
    }

    for (i = 1; i < argc; i++)
    {
        if (lstat(argv[i], &sb) == -1) 
        {
            perror(TERM_BRED("lstat"));
            return PARSE_ERROR;
        }

        if (print_stat_ls(argv[i], &sb) == -1)
            return PARSE_ERROR;
    }

    return PARSE_SUCCESS;
}

/**
 * @brief Get the recursive command value if exist else sets a default value
 *
 * @param def The default value to set if not exists any current value
 * @return Value string else NULL
 */
int *get_recursive() 
{
    static int recursive = 0;
    return &recursive;
}

/**
 * @brief Parse recursive command
 *
 * @return PARSE_SUCCESS on succes else PARSE_ERROR
 */
int parse_recursive(int argc, char **argv)
{
    int result = PARSE_SUCCESS;

    if (argv[1] == NULL) {
        printf("%s\n", *get_recursive() ? "ON" : "OFF");
    } 
    else if (!strcmp(argv[1], "ON")) {
        *get_recursive() = 1;        
    } 
    else if (!strcmp(argv[1], "OFF")) {
        *get_recursive() = 0;
    } 
    else 
    {
        printf("recursive: invalid option \"%s\"\n", argv[1]);
        result = PARSE_ERROR;

        print_recursive_usage();
    }

    return result;
}

/**
 * @brief Parse list command
 *
 * @return PARSE_SUCCESS on succes else PARSE_ERROR
 */
int parse_list(int argc, char **argv)
{
    int i;
    int flags = 0;
    int result = PARSE_SUCCESS;

    if (*get_recursive())
        flags |= LIST_FLAG_RECURSIVE;

    if (argv[1] == NULL) 
    {
        if (list_path(".", flags) == -1)
            result = PARSE_ERROR;
    }
    else if (!strcmp(argv[1], "-l")) 
    {
        if (argv[2] == NULL) {
            if (list_path(".", flags | LIST_FLAG_MLPRINT) == -1)
                result = PARSE_ERROR;
        } 
        else
        {
            for (i = 2; i < argc; i++)
            {
                if (list_path(argv[i], flags | LIST_FLAG_MLPRINT) == -1)
                    result = PARSE_ERROR;
            }
        }
    } 
    else 
    {
        for (i = 1; i < argc; i++)
        {
            if (list_path(argv[i], flags) == -1)
                result = PARSE_ERROR;
        }
    }

    return result;
}

/**
 * @brief Parse eliminate command
 *
 * @return PARSE_SUCCESS on succes else PARSE_ERROR
 */
int parse_eliminate(int argc, char **argv)
{
    int result = PARSE_SUCCESS;

    if (argv[1] == NULL) 
    {
        print_eliminate_usage();
        result = PARSE_ERROR;
    } 
    else if (!strcmp(argv[1], "-f")) 
    {
        if (argv[2] == NULL) {
            print_eliminate_usage();
            result = PARSE_ERROR;
        } 
        else 
        {        
            if (eliminate_path(argv[2], ELIMINATE_FLAG_FORCE) == -1)
                result = PARSE_ERROR;
        }
    } 
    else 
    {
        if (eliminate_path(argv[1], 0) == -1)
            result = PARSE_ERROR;
    }

    return result;
}

int parse_dealloc(int argc, char **argv)
{
    memory_record_t record = {0};    

    if (argc == 2) {
        print_memory_records(MEMORY_TYPE_MALLOC);
    } 
    else 
    {
        size_t size = strtoumax(argv[2], NULL, 10);
        if (errno == ERANGE || errno == EINVAL) {
            perror("strtoumax");
            return PARSE_ERROR;
        }

        if (size == 0) {
            printf("malloc needs at least 1 byte of memory.\n");
            return PARSE_ERROR;
        }

        if (free_malloc_record(size, &record))
            printf("free_malloc_record: cannot deallocate.\n");
        else
            printf("deallocated %zu at %p\n", record.size, record.memory);
    }
    return PARSE_SUCCESS;
}

int parse_malloc(int argc, char **argv)
{
    memory_record_t *record;

    if (argc > 1) 
    {
        if (!strcmp("-deallocate", argv[1]))
            return parse_dealloc(argc, argv);

        size_t size = strtoumax(argv[1], NULL, 10);
        if (errno == ERANGE || errno == EINVAL) {
            perror("strtoumax");
            return PARSE_ERROR;
        }

        if (size == 0) {
            printf("malloc needs at least 1 byte of memory.\n");
            return PARSE_ERROR;
        }

        if (create_malloc_record(size, &record)) {
            printf("create_malloc_record: cannot create malloc record.\n");
            return PARSE_ERROR;
        }

        printf("allocated %zu at %p\n", record->size, record->memory);
    } 
    else if (argc == 1) {
        print_memory_records(MEMORY_TYPE_MALLOC);
    } else
        print_malloc_usage();   
        
    return PARSE_SUCCESS;
}

int parse_munmap(int argc, char **argv)
{
    memory_record_t record = {0};    
    
    if (argc == 2) {
        print_memory_records(MEMORY_TYPE_MMAP);
    } 
    else 
    {
        if (free_mmap_record(argv[2], &record))
            printf("free_mmap_record: cannot unmap %s.\n", argv[2]);
        else
            printf("unmaped %s at %p\n", argv[2], record.memory);
    }
    return PARSE_SUCCESS;
}

int parse_mmap(int argc, char **argv)
{
    memory_record_t *record;

    if (argc > 1) 
    {
        if (!strcmp("-deallocate", argv[1]))
            return parse_munmap(argc, argv);

        const char *perms = argc > 2 ? argv[2] : NULL;

        if (create_mmap_record(argv[1], perms, &record)) {
            printf("create_mmap_record: cannot create mmap record.\n");
            return PARSE_ERROR;
        }

        printf("file %s mapped at %p\n", record->mr.filename, record->memory);
    } 
    else if (argc == 1) {
        print_memory_records(MEMORY_TYPE_MMAP);
    }
        
    return PARSE_SUCCESS;
}

int parse_sharednew(int argc, char **argv)
{
    memory_record_t *record;
    key_t key;
    size_t size;

    if (argc > 2)
    {
        key = strtoumax(argv[1], NULL, 10);
        if (errno == ERANGE || errno == EINVAL) {
            perror("strtoumax");
            return PARSE_ERROR;
        }

        size = strtoumax(argv[2], NULL, 10);
        if (errno == ERANGE || errno == EINVAL) {
            perror("strtoumax");
            return PARSE_ERROR;
        }

        if (create_shared_key(key, size)) {
            printf("create_shared_key: cannot create shared memory key.\n");
            return PARSE_ERROR;
        } 
        else 
        {
            if (map_shared_record(key, &record)) {                
                printf("map_shared_record: cannot map shared memory key.\n");
                return PARSE_ERROR;
            }

            printf("allocated shared memory (key: %d) at %p\n", record->sr.key, record->memory);
        }
    }
    else
        print_memory_records(MEMORY_TYPE_SHARED);

    return PARSE_SUCCESS;
}

int parse_unshare(int argc, char **argv) 
{
    key_t key;
    memory_record_t record;

    if (argc == 2) {
        print_memory_records(MEMORY_TYPE_SHARED);
    } 
    else 
    {
        key = strtoumax(argv[2], NULL, 10);
        if (errno == ERANGE || errno == EINVAL) {
            perror("strtoumax");
            return PARSE_ERROR;
        }

        if (unmap_shared_record(key, &record)) {
            printf("unmap_shared_record: cannot unmap shared record.\n");
            return PARSE_ERROR;
        }
        printf("unmapped shared memory (key: %d) at %p\n", key, record.memory);
    }
    return PARSE_SUCCESS;
}

int parse_shared(int argc, char **argv)
{
    key_t key;
    memory_record_t *record;

    if (argc > 1) 
    {
        if (!strcmp("-deallocate", argv[1]))
            return parse_unshare(argc, argv);

        key = strtoumax(argv[1], NULL, 10);
        if (errno == ERANGE || errno == EINVAL) {
            perror("strtoumax");
            return PARSE_ERROR;
        }
        
        if (map_shared_record(key, &record)) {            
            printf("map_shared_record: cannot map shared record.\n");
            return PARSE_ERROR;
        }

        printf("mapped shared memory (key: %d) at %p\n", record->sr.key, record->memory);
    } else 
        print_memory_records(MEMORY_TYPE_SHARED);

    return PARSE_SUCCESS;
}

int parse_rmkey(int argc, char **argv)
{
    key_t key;

    if (argc != 2) {
        print_rmkey_usage();
    } 
    else 
    {
        key = strtoumax(argv[1], NULL, 10);
        if (errno == ERANGE || errno == EINVAL) {
            perror("strtoumax");
            return PARSE_ERROR;
        }

        if (free_shared_key(key)) {
            printf("free_shared_record: cannot remove shared memory key.\n");
            return PARSE_ERROR;
        }

        printf("shared memory (key: %d) removed.\n", key);
    }
    return PARSE_SUCCESS;
}

int parse_allocation(int argc, char **argv)
{
    print_memory_records(-1);
    return PARSE_SUCCESS;
}

int parse_deallocate(int argc, char **argv)
{
    uintptr_t addr;

    if (argc < 2) {
        print_deallocate_usage();
        return PARSE_ERROR;
    }

    addr = str2uintptr(argv[1]);
    if (errno == ERANGE || errno == EINVAL) {
        printf("str2uintptr: bad address format.\n");
        print_deallocate_usage();
        return PARSE_ERROR;
    }
    
    if (free_memory_record((void*)addr)) {
        printf("free_memory_record: address not found.\n");
        return PARSE_ERROR;
    }

    return PARSE_SUCCESS;
}

int parse_mem(int argc, char **argv)
{
    static void *g_1, *g_2, *g_3;
    void *l_1, *l_2, *l_3;

    printf("functions:\n %p\n %p\n %p\n\n", (void*)print_authors_usage, (void*)print_info_usage, (void*)print_list_usage);
    printf("globals:\n %p\n %p\n %p\n\n", (void*)&g_1, (void*)&g_2, (void*)&g_3);
    printf("locals:\n %p\n %p\n %p\n\n", (void*)&l_1, (void*)&l_2, (void*)&l_3);
    return PARSE_SUCCESS;
}

void recursivefunction(size_t n) {
    static char global[2048];
    char local[2048];

    printf("n: %zu : %p\n", n, (void*)&n);
    printf("global: %p\n", (void*)global);
    printf("local: %p\n\n", (void*)local);

    if (n > 0)
        recursivefunction(n - 1);
}

int parse_recursivefunction(int argc, char **argv)
{
    size_t n;

    if (argc > 1) 
    {
        n = str2uintptr(argv[1]);
        if (errno == ERANGE || errno == EINVAL) {
            printf("str2uintptr: bad number format.\n");
            print_deallocate_usage();
            return PARSE_ERROR;
        }

        recursivefunction(n);
    } else 
        print_recursivefunction_usage();
    return PARSE_SUCCESS;
}

int parse_memdump(int argc, char **argv)
{
    uintptr_t addr;
    size_t size = 25;

    if (argc == 1) {
        print_memdump_usage();
    } 
    else 
    {
        if (argc > 2) 
        {
            size = str2uintptr(argv[2]);
            if (errno == ERANGE || errno == EINVAL) {
                printf("str2uintptr: bad size format.\n");
                printf("using default value: 25 bytes\n");
                size = 25;
            }
        }

        addr = str2uintptr(argv[1]);
        if (errno == ERANGE || errno == EINVAL) {
            printf("str2uintptr: bad address format.\n");
            print_deallocate_usage();
            return PARSE_ERROR;
        }

        memdump((void*)addr, size);
    }
    return PARSE_SUCCESS;
}

int parse_hexdump(int argc, char **argv)
{
    uintptr_t addr;
    size_t size = 25;

    if (argc == 1) {
        printf("Usage: hexdump addr [size]\n\n");
    } 
    else 
    {
        if (argc > 2) 
        {
            size = str2uintptr(argv[2]);
            if (errno == ERANGE || errno == EINVAL) {
                printf("str2uintptr: bad size format.\n");
                printf("using default value: 25 bytes\n");
                size = 25;
            }
        }

        addr = str2uintptr(argv[1]);
        if (errno == ERANGE || errno == EINVAL) {
            printf("str2uintptr: bad address format.\n");
            print_deallocate_usage();
            return PARSE_ERROR;
        }

        hexdump((void*)addr, size, 6, 4);
    }
    return PARSE_SUCCESS;
}

int parse_read(int argc, char **argv)
{
    uintptr_t addr;
    size_t size;

    if (argc < 3) {

    } 
    else 
    {
        addr = str2uintptr(argv[2]);
        if (errno == ERANGE || errno == EINVAL) {
            printf("str2uintptr: bad address format.\n");
            return PARSE_ERROR;
        }

        if (argc > 3)
        {
            size = str2uintptr(argv[3]);
            if (errno == ERANGE || errno == EINVAL) {
                printf("str2uintptr: bad size format.\n");
                return PARSE_ERROR;
            }

            read_to_mem(argv[1], (void*)addr, &size);
        }
        else
            read_to_mem(argv[1], (void*)addr, NULL);
    }

    return PARSE_SUCCESS;
}

int parse_write(int argc, char **argv)
{
    uintptr_t addr;
    size_t size;
    int create = 0;

    if (argc < 4) {

    } 
    else 
    {
        addr = str2uintptr(argv[2]);
        if (errno == ERANGE || errno == EINVAL) {
            printf("str2uintptr: bad address format.\n");
            return PARSE_ERROR;
        }

        size = str2uintptr(argv[3]);
        if (errno == ERANGE || errno == EINVAL) {
            printf("str2uintptr: bad size format.\n");
            return PARSE_ERROR;
        }

        if (argc > 4 && !strcmp("-o", argv[4]))
            create = 1;
        
        write_from_mem(argv[1], create, (void*)addr, size);
    }

    return PARSE_SUCCESS;
}

int parse_set_priority(int argc, char **argv)
{
    uintptr_t pid;
    intptr_t value;
    int prio;

    if (argc == 1) {
        //TODO: print usage
    } else if (argc == 2) {
        pid = parse_uintptr_or_return_error(argv[1]);

        errno = 0;
        prio = getpriority(PRIO_PROCESS, (pid_t)pid);
        if (prio == -1 && errno != 0) {
            perror("getpriority");
            return PARSE_ERROR;
        }

        printf("%d\n", prio);
    } else if (argc == 3) {
        pid = parse_uintptr_or_return_error(argv[1]);
        value = parse_intptr_or_return_error(argv[2]);

        prio = setpriority(PRIO_PROCESS, pid, value);
        if (prio == -1) {
            perror("setpriority");
            return PARSE_ERROR;
        }

        printf("Process %u priority set to %d\n", (unsigned)pid, (int)value);
    }

    return PARSE_SUCCESS;
}

int parse_fork(int argc, char **argv)
{
    pid_t pid = fork();

    if (pid == -1) {
        perror("fork");
        return PARSE_ERROR;
    } else if (pid != 0) {
        if (waitpid(pid, NULL, 0) == -1) {
            perror("waitpid");
            return PARSE_ERROR;
        }
    }

    return PARSE_SUCCESS;
}

void clear_searchlist() {
    setenv("SEARCH_LIST", "", 1);
}

const char *get_searchlist() {
    char *e = getenv("SEARCH_LIST");

    if (e != NULL)
        return e;
    
    if (setenv("SEARCH_LIST", "", 1) == -1)
        perror("setenv");
    return "";
}

const char *add_to_searchlist(const char *path) {
    if (path == NULL)
        return NULL;

    const char *ssl = get_searchlist();
    int sl = strlen(ssl);
    int pl = strlen(path);
    int bs = sl + pl + 2;
    char buff[bs];
    memset(buff, 0, bs * sizeof(char));

    snprintf(buff, bs, "%s%s%s", ssl, sl > 0 ? ":" : "", path);
    if (setenv("SEARCH_LIST", buff, 1) == -1) {
        perror("setenv");
        return NULL;
    }

    return get_searchlist();
}

void searchlist_search_exec(const char *name, char **out)
{
    if (name == NULL || strlen(name) < 1)
        return;

    int osize;
    int tlen;
    char *separator;
    char *token;
    const char *sl = get_searchlist();
    char *slcpy = malloc(sizeof(char) * strlen(sl) + 1);
    slcpy[0] = 0;
    strcat(slcpy, sl);

    token = strtok(slcpy, ":");
    if (token == NULL) {
        free(slcpy);
        return;
    }

    do
    {
        if (!find_executable(token, name)) 
        {
            tlen = strlen(token);
            separator = token[tlen - 1] != '/' ? "/" : "";

            if (out != NULL && *out == NULL) {
                osize = tlen + strlen(name) + 2;
                *out = malloc(sizeof(char) * osize);
                snprintf(*out, osize, "%s%s%s", token, separator, name);

                free(slcpy);
                return;
            }

            printf("%s%s%s\n", token, separator, name);
        }
    } while ((token = strtok(NULL, ":")));


    free(slcpy);
}

int parse_searchlist(int argc, char **argv)
{
    if (argc == 1) {
        printf("%s\n", get_searchlist());
    } 
    else if (argc == 2) 
    {
        switch (argv[1][0])
        {
            case '+':
                if (add_to_searchlist(argv[1] + 1) == NULL)
                    return PARSE_ERROR;
            break;
            case '-':
                if (!strcmp(argv[1], "-path"))
                    if (add_to_searchlist(getenv("PATH")) == NULL)
                        return PARSE_ERROR;
            break;
            default:
                searchlist_search_exec(argv[1], NULL);
            break;
        }
    }
    return PARSE_SUCCESS;
}

int parse_cmd_priority(int argc, char **argv, pid_t pid)
{
    int prio;
    intptr_t value;

    if (argc > 1 && argv[argc - 1][0] == '@') {
        value = parse_intptr_or_return_error(argv[argc - 1] + 1);

        prio = setpriority(PRIO_PROCESS, pid, value);
        if (prio == -1) {
            perror("setpriority");
            return -1;
        }

        argv[argc - 1] = NULL;
    }

    return 0;
}

int parse_exec(int argc, char **argv)
{
    char *path = NULL;

    if (argc < 2 || argv[1][0] == '@') {
        // TODO: Print usage
        return PARSE_ERROR;
    }

    if (parse_cmd_priority(argc, argv, getpid()))
        return PARSE_ERROR;

        // Absolute path
    if (argv[1][0] == '/' || 
        !strncmp(argv[1], "./", 2) || 
        !strncmp(argv[1], "../", 3)) 
    {
        if (execv(argv[1], &argv[1]) == -1)
            perror("execv");
    } else { // Searchlist path
        searchlist_search_exec(argv[1], &path);
        if (path == NULL) {        
            printf("%s: command not found\n", argv[1]);
            return PARSE_ERROR;
        }

        if (execv(path, &argv[1]) == -1)
            perror("execv");
        free(path);
    }
    
    return PARSE_ERROR;
}

int parse_unknown(int argc, char **argv)
{
    char *cmd = NULL;
    char *path = NULL;
    pid_t pid;

    // Absolute path
    if (argv[0][0] == '/' || 
        !strncmp(argv[0], "./", 2) || 
        !strncmp(argv[0], "../", 3)) {
        cmd = argv[0];
    } else { // Searchlist path
        searchlist_search_exec(argv[0], &path);
        if (path == NULL) {
            printf("%s: command not found\n", argv[0]);
            return PARSE_ERROR;
        }
        cmd = path;
    }

    pid = fork();
    if (pid == -1) {
        perror("fork");
        return PARSE_ERROR;
    }

    if (pid > 0)
    {
        if (path != NULL)
            free(path);

        waitpid(pid, NULL, 0);
        return PARSE_SUCCESS;
    }

    if (parse_cmd_priority(argc, argv, getpid()))
        return PARSE_ERROR;

    if (execv(cmd, argv) == -1)
        perror("execv");
    
    if (path != NULL)
        free(path);

    exit(-1);
}

int parse_background(int argc, char **argv)
{
    char *cmd = NULL;
    char *path = NULL;
    pid_t pid;

    if (argc < 2)
        return PARSE_ERROR;

    // Absolute path
    if (argv[1][0] == '/' || 
        !strncmp(argv[1], "./", 2) || 
        !strncmp(argv[1], "../", 3)) {
        cmd = argv[1];
    } else { // Searchlist path
        searchlist_search_exec(argv[1], &path);
        if (path == NULL) {        
            printf("%s: command not found\n", argv[1]);
            return PARSE_ERROR;
        }
        cmd = path;
    }

    pid = fork();
    if (pid == -1) {
        perror("fork");
        return PARSE_ERROR;
    }

    if (pid > 0)
    {
        if (path != NULL)
            free(path);

        if (create_job_record(pid, argc - 1, argv + 1))
            printf("Cannot create job record\n");
        return PARSE_SUCCESS;
    }

    if (parse_cmd_priority(argc, argv, getpid()))
        return PARSE_ERROR;

    if (execv(cmd, argv + 1) == -1)
        perror("execv");
    
    if (path != NULL)
        free(path);

    exit(-1);
}

int parse_jobs(int argc, char **argv)
{
    print_job_records();
    return PARSE_SUCCESS;
}

int parse_proc(int argc, char **argv)
{
    pid_t pid;

    if (argc < 2) {
        print_job_records();
    } 
    else 
    {
        pid = (pid_t)parse_uintptr_or_return_error(argv[1]);
        if (print_job_record_by_pid(pid))
            print_job_records();
    }

    return PARSE_SUCCESS;
}

int parse_clearjobs(int argc, char **argv)
{
    clear_job_records();
    return PARSE_SUCCESS;
}

int main()
{
    clear_searchlist();

    char line[MAX_CMD_LENGTH];
    char *cargv[MAX_CMD_LENGTH / 2];
    int cargc;

    struct parse_command_entry unk = { NULL, parse_unknown };

    struct parse_command_entry cmds[] = {    
        { "exit", parse_exit },
        { "fin", parse_exit },
        { "end", parse_exit },
        { "autores", parse_authors },
        { "pid", parse_pid },
        { "info", parse_info },
        { "recursive", parse_recursive },
        { "list", parse_list },
        { "eliminate", parse_eliminate },
        { "malloc", parse_malloc },
        { "mmap", parse_mmap },
        { "sharednew", parse_sharednew },
        { "shared", parse_shared },
        { "rmkey", parse_rmkey },
        { "allocation", parse_allocation },
        { "deallocate", parse_deallocate },
        { "mem", parse_mem },
        { "memdump", parse_memdump },
        { "hexdump", parse_hexdump },
        { "recursivefunction", parse_recursivefunction },
        { "read", parse_read },
        { "write", parse_write },
        { "setpriority", parse_set_priority },
        { "fork", parse_fork },
        { "searchlist", parse_searchlist },
        { "exec", parse_exec },
        { "background", parse_background },
        { "jobs", parse_jobs },
        { "proc", parse_proc },
        { "clearjobs", parse_clearjobs },
        { NULL, NULL } // Last entry
    };

    do
    {
        print_prompt();
        fgets(line, MAX_CMD_LENGTH, stdin);
        split_line(line, &cargc, cargv, MAX_CMD_LENGTH / 2);
    } while (parse_line(cargc, cargv, cmds, &unk) != PARSE_EXIT);

    free_memory_records();
    clear_job_records();

    return EXIT_SUCCESS;
}
