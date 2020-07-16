#include "common.h"
#include "list.h"
#include "listproc.h"
#include "signal.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <glob.h>
#include <inttypes.h>
#include <stdint.h>
#include <ctype.h>


// Permissions string max characteres with '\0' included
#define PERM_STR_MAX 12


int perrorf(const char *format, ...) 
{    
    va_list va;
    int e = errno;
    int c0, c1;

    va_start(va, format);
    c0 = vprintf(format, va);
    va_end(va);

    if (c0 == -1)
        return -1;

    c1 = printf(":%s\n", strerror(e));
    if (c1 == -1)
        return -1;

    return c0 + c1;
}

char *concat_path(const char *left, const char *right, int is_dir) 
{
    int llen, rlen, len;
    char *str;
    
    llen = strlen(left);
    rlen = strlen(right);

    // Assure size for a separator and end of string chars
    len = llen + rlen + 3;
    str = (char*)malloc(len * sizeof(char));

    if (str == NULL) 
        return NULL;

    str[0] = '\0';

    strcat(str, left);
    if (left[llen - 1] != '/' && right[0] != '/')
        strcat(str, "/");
    strcat(str, right);
    if (is_dir)
        strcat(str, "/");
    
    return str;
}

/**
 * @brief Writes the file permissions as string in a buffer
 *
 * @param buff Destination buffer
 * @param size Buffer size, at least of the size PERM_STR_MAX
 * @return 0 on success else -1
 */
int perm_to_str(mode_t m, void *buff, size_t size)
{
    char *cbuff = (char*)buff;
    int xusr, xgrp, xoth;

    if (size < PERM_STR_MAX)
        return -1;

    switch (m & S_IFMT)
    {
        case S_IFSOCK: cbuff[0] = 's'; break; // socket
        case S_IFLNK:  cbuff[0] = 'l'; break; // symbolic link
        case S_IFREG:  cbuff[0] = '-'; break; // regular file
        case S_IFBLK:  cbuff[0] = 'b'; break; // block device
        case S_IFDIR:  cbuff[0] = 'd'; break; // directory
        case S_IFCHR:  cbuff[0] = 'c'; break; // char device
        case S_IFIFO:  cbuff[0] = 'p'; break; // pipe         
        default:       cbuff[0] = '?'; break; // unknown
    }

    // owner
    cbuff[1] = (m & S_IRUSR) ? 'r' : '-';
    cbuff[2] = (m & S_IWUSR) ? 'w' : '-';    

    // group
    cbuff[4] = (m & S_IRGRP) ? 'r' : '-';    
    cbuff[5] = (m & S_IWGRP) ? 'w' : '-';    

    // others
    cbuff[7] = (m & S_IROTH) ? 'r' : '-';    
    cbuff[8] = (m & S_IWOTH) ? 'w' : '-';

    xoth = m & S_IXOTH;
    xusr = m & S_IXUSR;
    xgrp = m & S_IXGRP;

    cbuff[3] = (m & S_ISUID) ? (xusr ? 's' : 'S') : (xusr ? 'x' : '-');
    cbuff[6] = (m & S_ISGID) ? (xgrp ? 's' : 'S') : (xgrp ? 'x' : '-');
    cbuff[9] = (m & S_ISVTX) ? (xoth ? 't' : 'T') : (xoth ? 'x' : '-');    

    cbuff[10] = ' '; // + for acls
    cbuff[11] = '\0';    
    return 0;
}
 
/**
 * @brief Gets the month ls string from a tm struct
 *
 * @return The month string else "unk"
 */
const char *month_to_str(const struct tm *tm_time) 
{
    switch (tm_time->tm_mon)
    {				
        case 0: return "jan";
        case 1: return "feb";
        case 2: return "mar";
        case 3: return "apr";
        case 4: return "may";
        case 5: return "jun";
        case 6: return "jul";
        case 7: return "aug";
        case 8: return "sep";
        case 9: return "oct";
        case 10: return "nov";
        case 11: return "dec";
        default: return "unk";
    }
}

int print_stat_ls(const char *path, const struct stat *sb) 
{
    char permissions[PERM_STR_MAX];
    struct passwd *pwd;
    struct group *grp;
    struct tm *tm_time;
    char sufix[PATH_MAX + NAME_MAX + 5] = {0};

    pwd = getpwuid(sb->st_uid);
    if (pwd == NULL) {
        perror(TERM_BRED("getpwuid"));
        return -1;
    }

    grp = getgrgid(sb->st_gid);    
    if (grp == NULL) {
        perror(TERM_BRED("getgrgid"));
        return -1;
    }

    tm_time = localtime(&sb->st_mtime);    
    if (tm_time == NULL) {
        perror(TERM_BRED("localtime"));
        return -1;
    }

    perm_to_str(sb->st_mode, permissions, PERM_STR_MAX);

    switch (sb->st_mode & S_IFMT) 
    {
        case S_IFLNK:
            // Get the link real path
            if (readlink(path, sufix + 4, PATH_MAX + NAME_MAX) == -1) {
                perrorf(TERM_BRED("%s")":"TERM_BRED("readlink"), path);
                return -1;
            }

            memcpy(sufix, " -> ", sizeof(char) * 4);
        break;
    }

    printf("%6ld %11s %4lu %s %s %6ld %3s %2d %02d:%02d %s%s\n", 
        sb->st_ino, permissions, 
        sb->st_nlink, pwd->pw_name, grp->gr_name, 
        sb->st_size, month_to_str(tm_time), 
        (int)tm_time->tm_mday, (int)tm_time->tm_hour, 
        (int)tm_time->tm_min, path, sufix); 

    return 0;
}

void print_stat_list(const char *path, const struct stat *sb)
{
    printf("%8ld %s\n", sb->st_size, path);
}

int list_print(const char *path, const struct stat *sb, int flags)
{    
    int poff = 0;

    // Remove the ./ at start if exist
    if (path[0] == '.' && path[1] == '/')
        poff = 2;

    // Print with the mode specified
    if (flags & LIST_FLAG_MLPRINT) 
        print_stat_ls(path + poff, sb);
    else
        print_stat_list(path, sb);    
    return 0;
}

int list_path_rec(const char *path, int deep, int flags)
{
    struct stat sb;
    char *cpath;
    DIR *dp;
    struct dirent *ep;
    int max_deep = 1;

    if (lstat(path, &sb) == -1) {
        perrorf(TERM_BRED("%s")":"TERM_BRED("stat"), path);
        return -1;
    }

    if (flags & LIST_FLAG_RECURSIVE)
        max_deep = -1;

    list_print(path, &sb, flags);

    if ( ((sb.st_mode & S_IFMT) == S_IFDIR) && 
         (max_deep < 0 || deep < max_deep) ) 
    {
        dp = opendir(path);
        if (dp == NULL) {                        
            perrorf(TERM_BRED("%s")":"TERM_BRED("opendir"), path);
            return -1;
        }

        while ((ep = readdir(dp)))
        {
            if (!strcmp(ep->d_name, ".") || !strcmp(ep->d_name, ".."))
                continue;

            cpath = concat_path(path, ep->d_name, 0);
            if (cpath == NULL) {
                printf(TERM_BRED("concat_path")": cannot allocate memory\n");
                return -1;
            }

            list_path_rec(cpath, deep + 1, flags);
            free(cpath);
        }

        if (closedir(dp) == -1) {
            perrorf(TERM_BRED("%s")":"TERM_BRED("closedir"), path);
            return -1;
        }
    }

    return 0;
}

int list_path(const char *path, int flags)
{
    return list_path_rec(path, 0, flags);
}

int eliminate_callback(const char *path, const struct stat *sb, int flags)
{  
    if (remove(path) == -1) {
        perrorf(TERM_BRED("%s")":"TERM_BRED("remove"), path);
        return -1;
    }    
    
    printf("Removed: %s\n", path);
    return 0;
}

int eliminate_path(const char *path, int flags)
{
    struct stat sb;
    char *cpath;
    DIR *dp;
    struct dirent *ep;

    if (lstat(path, &sb) == -1) {
        perrorf(TERM_BRED("%s")":"TERM_BRED("stat"), path);
        return -1;
    }

    if ( ((sb.st_mode & S_IFMT) == S_IFDIR) && (flags & ELIMINATE_FLAG_FORCE) ) 
    {
        dp = opendir(path);
        if (dp == NULL) {                        
            perrorf(TERM_BRED("%s")":"TERM_BRED("opendir"), path);
            return -1;
        }

        while ((ep = readdir(dp)))
        {
            if (!strcmp(ep->d_name, ".") || !strcmp(ep->d_name, ".."))
                continue;

            cpath = concat_path(path, ep->d_name, 0);
            if (cpath == NULL) {
                printf(TERM_BRED("concat_path")": cannot allocate memory\n");
                return -1;
            }

            if (eliminate_path(cpath, flags) == -1)
            {
                free(cpath);
                return -1;
            }
            free(cpath);
        }

        if (closedir(dp) == -1) {
            perrorf(TERM_BRED("%s")":"TERM_BRED("closedir"), path);
            return -1;
        }
    }

    return eliminate_callback(path, &sb, flags);
}

#define list_node_record(n) (memory_record_t*)list_node_value((n))
#define list_insert_record_after(n, r) list_insert_after(n, r, sizeof(memory_record_t))

list_t **get_memory_list() {
    static list_t *l = NULL;

    if (l == NULL) {
        if (list_create(&l)) {
            printf("list_create: cannot create list.\n");
            return NULL;
        }
    }

    return &l;
}

int create_malloc_record(size_t size, memory_record_t **r) 
{
    memory_record_t record;
    record.type = MEMORY_TYPE_MALLOC;

    time(&record.time);
    record.size = size;
    record.memory = malloc(record.size);

    if (record.memory == NULL) {
        perror("malloc:");
        return -1;
    }

    *r = list_node_record(list_insert_record_after(*get_memory_list(), &record));
    return *r ? 0 : -1;
}

int create_mmap_record(const char *filename, const char *perms, memory_record_t **r)
{
    char bperms[4] = {0};
    int iperms = PROT_NONE;
    struct stat sb;
    memory_record_t record;

    if (perms)
    {
        strcat(bperms, perms);
        iperms |= bperms[0] == 'r' ? PROT_READ : 0; 
        iperms |= bperms[1] == 'w' ? PROT_WRITE : 0;
        iperms |= bperms[2] == 'x' ? PROT_EXEC : 0;
    }

    record.type = MEMORY_TYPE_MMAP;
    time(&record.time);
    
    record.mr.fd = open(filename, O_RDONLY);

    if (record.mr.fd == -1) {
        perror("open");
        return -1;
    }

    if (fstat(record.mr.fd, &sb) == -1) {
        close(record.mr.fd);
        perror ("fstat");
        return -1;
    }

    if (!S_ISREG (sb.st_mode)) {
        close(record.mr.fd);
        printf("%s is not a file.\n", filename);
        return -1;
    }
    
    record.size = sb.st_size;
    record.memory = mmap(0, record.size, iperms, MAP_PRIVATE, record.mr.fd, 0);
    if (record.memory == MAP_FAILED) {
        perror("map_file");
        return -1;
    }

    record.mr.filename = (char*)malloc(sizeof(char) * (strlen(filename) + 1));
    if (record.mr.filename) {
        record.mr.filename[0] = 0;
        strcat(record.mr.filename, filename);
    } else {
        printf("malloc: cannot allocate memory.\n");
        munmap(record.memory, record.size);
        close(record.mr.fd);
        return -1;
    }

    *r = list_node_record(list_insert_record_after(*get_memory_list(), &record));
    return *r ? 0 : -1;
}

int create_shared_key(key_t key, size_t size)
{
    if (shmget(key, size, IPC_CREAT | IPC_EXCL | 0666) == -1)
    {
        perror("shmget");
        return -1;
    }

    return 0;
}

int free_malloc_record(size_t size, memory_record_t *r)
{
    memory_record_t *record;
    struct list_node *node = *get_memory_list();

    while ((node = list_next(node))) 
    {
        record = list_node_record(node);
        if (record->type == MEMORY_TYPE_MALLOC && record->size == size) 
        {
            free(record->memory);

            if (r) *r = *record;
            list_remove(*get_memory_list(), node);
            return 0;
        }
    }

    return -1;
}

int free_mmap_record(const char *filename, memory_record_t *r)
{
    memory_record_t *record;
    struct list_node *node = *get_memory_list();

    while ((node = list_next(node))) 
    {
        record = list_node_record(node);
        if ( record->type == MEMORY_TYPE_MMAP && 
             !strcmp(record->mr.filename, filename) ) 
        {
            munmap(record->memory, record->size);
            close(record->mr.fd);
            free(record->mr.filename);
            record->mr.filename = NULL;

            if (r) *r = *record;
            list_remove(*get_memory_list(), node);
            return 0;
        }
    }

    return -1;
}

int free_shared_key(key_t key)
{
    int id;

    id = shmget(key, 0, 0666);
    
    if (id == -1) {
        perror("shmget");
        return -1;
    }

    if (shmctl(id, IPC_RMID, NULL) < 0) {
        perror("shmctl");
        return -1;
    }

    return 0;
}

int free_memory_record(void *address)
{
    memory_record_t *record;
    struct list_node *node = *get_memory_list();

    while ((node = list_next(node))) 
    {
        record = list_node_record(node);
        if (record->memory == address) 
        {
            switch (record->type)
            {
                case MEMORY_TYPE_MALLOC:
                    free(record->memory);
                    break;
                case MEMORY_TYPE_MMAP:
                    munmap(record->memory, record->size);
                    close(record->mr.fd);
                    free(record->mr.filename);
                    record->mr.filename = NULL;
                    break;
                case MEMORY_TYPE_SHARED:
                    if (shmdt(record->memory) == -1)
                        perror("shmdt");
                    break;
            }

            list_remove(*get_memory_list(), node);
            return 0;
        }
    }

    return -1;
}

int free_memory_records()
{
    memory_record_t *record;

    struct list_node *node = *get_memory_list();
    while ((node = list_next(node))) 
    {
        record = list_node_record(node);
        switch (record->type) {
            case MEMORY_TYPE_MALLOC:
                free(record->memory);
            break;
            case MEMORY_TYPE_MMAP:
                munmap(record->memory, record->size);
                close(record->mr.fd);
                free(record->mr.filename);
                record->mr.filename = NULL;
            break;
            case MEMORY_TYPE_SHARED:
                if (shmdt(record->memory) == -1)
                    perror("shmdt");                
                free_shared_key(record->sr.key);
                break;
        }
    }

    list_delete(get_memory_list());
    return 0;
}

int map_shared_record(key_t key, memory_record_t **r)
{
    int id;
    memory_record_t lrecord;
    struct shmid_ds shmds;
    
    id = shmget(key, 0, 0666);
    
    if (id == -1) 
    {
        perror("shmget");
        return -1;
    }

    if (shmctl(id, IPC_STAT, &shmds) == -1) 
    {
        perror("shmctl");
        return -1;
    }

    lrecord.type = MEMORY_TYPE_SHARED;
    lrecord.memory = shmat(id, NULL, 0);
    if (lrecord.memory == (void*)-1) 
    {
        perror("shmat");
        return -1;
    }

    lrecord.sr.key = key;
    time(&lrecord.time);
    lrecord.size = shmds.shm_segsz;

    *r = list_node_record(list_insert_record_after(*get_memory_list(), &lrecord));
    return *r ? 0 : -1;
}

int unmap_shared_record(key_t key, memory_record_t *r)
{
    memory_record_t *record;
    struct list_node *node = *get_memory_list();

    while ((node = list_next(node))) 
    {
        record = list_node_record(node);
        if ( record->type == MEMORY_TYPE_SHARED && 
             record->sr.key == key ) 
        {            
            if (shmdt(record->memory) == -1) {
                perror("shmdt");
                return -1;
            }            

            if (r) *r = *record;

            record->memory = NULL;
            list_remove(*get_memory_list(), node);
            return 0;
        }
    }
    return -1;
}

int print_memory_record(memory_record_t *r)
{
    char ts[256] = {0};
    if (r == NULL)
        return -1;

    struct tm *tm_time = localtime(&r->time);
    strftime(ts, 255, "%a %b %d %H:%M:%S %Y", tm_time);
    switch (r->type)
    {
        case MEMORY_TYPE_MALLOC:
            printf("%p : %zu : malloc : %s\n", r->memory, r->size, ts);
        break;
        case MEMORY_TYPE_MMAP:
            printf("%p : %zu : mmap %s (fd: %d) : %s\n", r->memory, r->size, r->mr.filename, r->mr.fd, ts);
        break;
        case MEMORY_TYPE_SHARED:            
            printf("%p : %zu : shared (key: %d) : %s\n", r->memory, r->size, r->sr.key, ts);
        break;
    }
    return 0;
}

void print_memory_records(int type)
{
    struct list_node *node = *get_memory_list();
    while ((node = list_next(node)))
    {
        memory_record_t *r = list_node_record(node);
        if (r->type == type || type == -1)
            print_memory_record(r);
    }
}

int isnum(char c) {
    return c >= '0' && c <= '9';
}

uintptr_t str2uintptr(const char *s) {
    return (uintptr_t)strtoumax(s, NULL, 0);
}

intptr_t str2intptr(const char *s) {
    return (intptr_t)strtoimax(s, NULL, 0);
}

void hexdump(const void *p, size_t size, int cols, int col_bytes)
{
    int addr_col_len = sizeof(void*) * 2;

    int i, j;
    int row_len = col_bytes * cols;    
    int rest = size % row_len;
    const unsigned char *buff = (const unsigned char*)p;

    printf("   %*.s", addr_col_len, "");
    for (i = 0; i <  cols; i++)
        printf(" %0*d", col_bytes * 2, i * col_bytes);
    printf("\n");    

    if (size > row_len)
        for (i = 0; i < size - rest; i += row_len) 
        {
            printf("0x%0*" PRIxPTR " ", addr_col_len, (uintptr_t)&buff[i]);

            for (j = 0; j < row_len; j++) {
                if (j % col_bytes == 0) printf(" ");
                printf("%02x", buff[i + j]);
            }

            printf(" ");

            for (j = 0; j < row_len; j++)
                if (isprint(buff[i + j]))
                    printf("%c", buff[i + j]);
                else printf(".");
            
            printf("\n");
        }

    if (rest != 0)
    {
        i = 0;
        printf("0x%0*" PRIxPTR " ", addr_col_len, (uintptr_t)&buff[i]);

        for (j = 0; j < rest; j++) {
            if (j % col_bytes == 0) printf(" ");
            printf("%02x", buff[i + j]);
        }
        
        for (j = rest; j < row_len; j++) {
            if (j % col_bytes == 0) printf(" ");
            printf("%*.s", 2, "");
        }

        printf(" ");

        for (j = 0; j < rest; j++)
            if (isprint(buff[i + j]))
                printf("%c", buff[i + j]);
            else printf(".");
        
        printf("\n");
    }
}

void memdump(const void *p, size_t size)
{
    int i;
    int l = size > 24 ? 24 : size;
    const unsigned char *cp = (const unsigned char*)p;

    while (size)
    {
        for (i = 0; i < l; i++)
            if (isprint(*(cp + i)))
                printf("%2c ", *(cp + i));
            else printf(" . ");

        printf("\n");

        for (i = 0; i < l; i++)
            printf("%02x ", (unsigned int)*(cp + i));

        printf("\n");

        cp += l;
        size -= l;
        l = size > 24 ? 24 : size;
    }
}

int read_to_mem(const char *filename, void *dst, size_t *size) 
{    
    struct stat sb;
    int fd;
    
    fd = open(filename, O_RDONLY);

    if (fd == -1) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &sb) == -1) {
        close(fd);
        perror ("fstat");
        return -1;
    }

    if (!S_ISREG (sb.st_mode)) {
        close(fd);
        printf("%s is not a file.\n", filename);
        return -1;
    }

    read(fd, dst, size ? *size : sb.st_size);

    if (close(fd) == -1) {
        perror("close");
        return -1;
    }

    return 0;
}

int write_from_mem(const char *filename, int create, void *src, size_t size)
{
    struct stat sb;
    int fd;
    
    fd = open(filename, create ? O_WRONLY | O_CREAT : O_WRONLY, 0777);

    if (fd == -1) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &sb) == -1) {
        close(fd);
        perror ("fstat");
        return -1;
    }

    if (!S_ISREG (sb.st_mode)) {
        close(fd);
        printf("%s is not a file.\n", filename);
        return -1;
    }

    write(fd, src, size);

    if (close(fd) == -1) {
        perror("close");
        return -1;
    }

    return 0;
}

int find_executable(const char *path, const char *name)
{
    struct stat sb;
    char *cpath;
    DIR *dp;
    struct dirent *ep;

    if (lstat(path, &sb) == -1)
        return -1;    

    if ((sb.st_mode & S_IFMT) == S_IFDIR) 
    {
        dp = opendir(path);
        if (dp == NULL)
            return -1;

        while ((ep = readdir(dp)))
        {
            if (!strcmp(ep->d_name, ".") || !strcmp(ep->d_name, ".."))
                continue;

            cpath = concat_path(path, ep->d_name, 0);
            if (cpath == NULL) {
                printf(TERM_BRED("concat_path")": cannot allocate memory\n");
                return -1;
            }

            if (!strcmp(ep->d_name, name) && 
                strlen(ep->d_name) == strlen(name)) 
            {
                if (lstat(cpath, &sb) != -1) 
                {
                    if ((sb.st_mode & S_IFMT) != S_IFDIR && 
                        (sb.st_mode & S_IXUSR ||
                        sb.st_mode & S_IXGRP ||
                        sb.st_mode & S_IXOTH)) 
                    {
                            
                            free(cpath);
                            closedir(dp);
                            return 0;                
                    }
                }
            }

            free(cpath);
        }

        if (closedir(dp) == -1) {
            perrorf(TERM_BRED("%s")":"TERM_BRED("closedir"), path);
            return -1;
        }
    }

    return -1;
}

plist_t **get_jobs_plist() {
    static plist_t *l = NULL;

    if (l == NULL) {
        if (plist_create(&l)) {
            printf("plist_create: cannot create list.\n");
            return NULL;
        }
    }

    return &l;
}

void print_job_status(job_record_t *j) {
    if (j->active)
        printf("ACTIVE");
    else if (WIFEXITED(j->status))
        printf("TERMINATED (%u)", (unsigned)WEXITSTATUS(j->status));
    else if (WIFSTOPPED(j->status))
        printf("STOPPED (%s)", sig_to_str(WSTOPSIG(j->status)));
#ifdef WIFCONTINUED
    else if (WIFCONTINUED(j->status))
        printf("CONTINUED (%s)", sig_to_str(SIGCONT));
#endif
    else if (WIFSIGNALED(j->status))
        printf("SIGNALED (%s)", sig_to_str(WTERMSIG(j->status)));
}

int update_job_status(job_record_t *j) {    
    int prio;

    j->active = waitpid(j->pid, &j->status, WNOHANG | WUNTRACED | WCONTINUED) == 0;

    errno = 0;
    prio = getpriority(PRIO_PROCESS, j->pid);
    if (errno == 0)
      j->priority = prio;

    return 0;
}

int create_job_record(pid_t pid, int argc, char **argv)
{
    int i;
    job_record_t j;
    size_t cs = 1;

    j.pid = pid;
    time(&j.time);
    j.cmdline = NULL;

    for (i = 0; i < argc; i++)
        cs += strlen(argv[i]);
    
    if (cs > 1) {
        cs += argc;
        j.cmdline = (char*)malloc(cs * sizeof(char));
        j.cmdline[0] = 0;

        for (i = 0; i < argc; i++) {
            strcat(j.cmdline, argv[i]);
            strcat(j.cmdline, " ");
        }
    }

    if (!update_job_status(&j))
        return plist_add(*get_jobs_plist(), &j, sizeof(job_record_t)) ? 0 : -1;
    return -1;
}

int clear_job_records() {
    int i;
    plist_t **l = get_jobs_plist();
    if (l == NULL) return -1;

    for (i = 0; i < plist_size(*l); i++)
    {
        job_record_t *r = (job_record_t*)plist_value_at(*l, i);
        if (r->cmdline != NULL)
            free(r->cmdline);
    }

    return plist_delete(get_jobs_plist());
}

void print_job_record(job_record_t *j)
{
    char ts[256] = {0};
    struct tm *tm_time;

    tm_time = localtime(&j->time);
    strftime(ts, 255, "%a %b %d %Y %H:%M", tm_time);

    printf("%d\t", j->pid);
    print_job_status(j);
    printf("\tp=%d\t%s\t%s\n", j->priority, ts, 
                               j->cmdline ? j->cmdline : "");
}

int print_job_record_by_pid(pid_t pid)
{

    int i;
    plist_t **l = get_jobs_plist();
    if (l == NULL) return -1;

    for (i = 0; i < plist_size(*l); i++)
    {
        job_record_t *r = (job_record_t*)plist_value_at(*l, i);
        if (r->pid == pid) {
            update_job_status(r);
            print_job_record(r);
            return 0;
        }
    }
    return -1;
}

void print_job_records()
{
    int i;
    plist_t **l = get_jobs_plist();
    if (l == NULL) return;

    for (i = 0; i < plist_size(*l); i++)
    {
        job_record_t *r = (job_record_t*)plist_value_at(*l, i);
        update_job_status(r);
        print_job_record(r);
    }
}