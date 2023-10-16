#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>  
#include <stdint.h>
#include <stdarg.h>    //Defines macros to handle variable argument lists such as va_list, va_start, va_arg, va_end
#include <fcntl.h>     //Defines file control options such as O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_APPEND, etc. The open function from this header is also used.
#include <unistd.h>    //Defines POSIX operating system API such as fork, exec, pipe, 
#include <string.h>
#include <limits.h>    //Defines various constants related to data types, such as the maximum and minimum values for integer data types.
#include <errno.h>
#include <sys/stat.h>  //Defines structures and functions for working with file metadata such as struct stat, fstat, chmod, chown, etc.
#include <sys/types.h> //Defines various types used in system calls such as size_t, pid_t, mode_t, etc.
#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <elf.h>


char *cur_command;
char *input_command;
char *node_name;
char *read_filter;

long int record[5];

static int (*real_open)(const char *, int, ...);
int myopen(const char *path, int flags, ...);

static ssize_t (*real_read)(int, void *, size_t);
ssize_t myread(int fd, void *buf, size_t count);


static ssize_t (*real_write)(int, void *, size_t);
ssize_t mywrite(int fd, void *buf, size_t count);

static int (*real_connect)(int, const struct sockaddr*, socklen_t);
int myconnect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

static int (*real_getaddrinfo)(const char *restrict, const char *restrict, const struct addrinfo *restrict,struct addrinfo **restrict);
int mygetaddrinfo(const char *restrict node, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res);

static int (*real_system)(const char*);
int mysystem(const char *command);

size_t get_executable_path (char* buffer, size_t len)
{
    char* path_end;
    /* Read the target of /proc/self/exe. */
    if (readlink ("/proc/self/exe", buffer, len) <= 0)
    return -1;
    /* Find the last occurrence of a forward slash, the path separator. */
    path_end = strrchr (buffer, '/');
    if (path_end == NULL)
    return -1;
    /* Advance to the character past the last slash. */
    ++path_end;
    /* Obtain the directory containing the program by truncating the
    path after the last slash. */
    *path_end = '\0';
    /* The length of the path is the number of characters up through the
    last slash. */
    return (size_t) (path_end - buffer);
}

char* getReadFilter(){
    char *filename = getenv("SANDBOX_CONFIG");
    if (filename == NULL) {
        printf("SANDBOX_CONFIG 環境變數未設置\n");
        return 1;
    }
    
    // 打開檔案
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("無法打開檔案 %s\n", filename);
        return 1;
    }

    char *line = NULL;
    size_t line_length = 0;
    ssize_t read;
    int in_blacklist = 0;
    char *filter_str = NULL;

    char *begin = "BEGIN read-blacklist";
    char *end = "END read-blacklist";
    while ((read = getline(&line, &line_length, fp)) != -1) {
        // 如果在 BEGIN open-blacklist 和 END open-blacklist 之間，加入到 blacklist 陣列中
        if (in_blacklist) {
            if (strstr(line, end) != NULL) {
                in_blacklist = 0;
            } else {
                // 去掉換行符
                line[strcspn(line, "\n")] = '\0';

                filter_str = strdup(line);
            }
        } else if (strstr(line, begin) != NULL) {
            in_blacklist = 1;
        }
    }
    free(line);
    fclose(fp);

    return filter_str;
}

int isBlackList(char *func_name, const char* compare_str){
    char *filename = getenv("SANDBOX_CONFIG");
    if (filename == NULL) {
        printf("SANDBOX_CONFIG 環境變數未設置\n");
        return 1;
    }
    
    // 打開檔案
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("無法打開檔案 %s\n", filename);
        return 1;
    }
    
    // 定義變數
    char *line = NULL;
    size_t line_length = 0;
    ssize_t read;
    int in_blacklist = 0;
    char **blacklist = NULL;
    int blacklist_size = 0;
    
    char *begin = "BEGIN ";
    char *end = "END ";
    char *suffix = "-blacklist";
    char combined_begin[strlen(begin) + strlen(func_name) + strlen(suffix) + 1]; //"BEGIN open-blacklist"
    char combined_end[strlen(end) + strlen(func_name) + strlen(suffix) + 1]; //"END open-blacklist"
    sprintf(combined_begin, "%s%s%s", begin, func_name, suffix);
    sprintf(combined_end, "%s%s%s", end, func_name, suffix);
    // 讀取檔案內容，逐行處理
    while ((read = getline(&line, &line_length, fp)) != -1) {
        // 如果在 BEGIN open-blacklist 和 END open-blacklist 之間，加入到 blacklist 陣列中
        if (in_blacklist) {
            if (strstr(line, combined_end) != NULL) {
                in_blacklist = 0;
            } else {
                // 去掉換行符
                line[strcspn(line, "\n")] = '\0';

                // 把字串加入到 blacklist 陣列中
                blacklist_size++;
                blacklist = realloc(blacklist, sizeof(char*) * blacklist_size);
                blacklist[blacklist_size - 1] = strdup(line);
            }
        } else if (strstr(line, combined_begin) != NULL) {
            in_blacklist = 1;
        }
    }
    free(line);
    fclose(fp);
    
    // 輸出 blacklist 陣列中的內容
    // printf("blacklist = [");
    int is_block = 0;
    char r_path[PATH_MAX];
    for (int i = 0; i < blacklist_size; i++) {
        // printf("\"%s\"", blacklist[i]);
        // if (i < blacklist_size - 1) {
        //     printf(", ");
        // }
        if(func_name == "read"){
            if (strstr(compare_str, blacklist[i]) != NULL) {
                is_block = 1;
            }
        }
        else if(func_name == "open"){
            if(realpath(blacklist[i], r_path) == NULL){
                // perror("realpath");
            }

            // printf("blaklist[%d]: [%s]\n", i ,blaklist[i]);
            // printf("r_path[%d]: [%s]\n\n", i ,r_path);
            if (strcmp(compare_str, r_path) == 0) {
                is_block = 1;
            }
        }
        else{
            if (strcmp(compare_str, blacklist[i]) == 0) {
                is_block = 1;
            }
        }
        // printf("%s  %s %d\n\n",  compare_str, blacklist[i], is_block);
        free(blacklist[i]);
    }
    free(blacklist);
    // printf("]\n");
    return is_block;
}

void Redirect(long offset, const char *replace_func_name){
    if(mprotect(record[3], record[4]-record[3], PROT_WRITE | PROT_READ) <0){
        printf("%s\n", replace_func_name);
        fprintf(stderr, "error is: %s\n", strerror(errno));
    };
    
    long int* correct_addr= record[0] + offset;
    // printf("%p\n", (void *)correct_addr);

    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Failed to open libc.so.6: %s\n", dlerror());
        return;
    }

    if (strcmp(replace_func_name, "open") == 0) {
        real_open = dlsym(handle, replace_func_name);
        if (!real_open) {
            fprintf(stderr, "Failed to find real open function: %s\n", dlerror());
            dlclose(handle);
            return;
        }
       *correct_addr = myopen;
    }else if (strcmp(replace_func_name, "read") == 0) {
        real_read = dlsym(handle, replace_func_name);
        if (!real_read) {
            fprintf(stderr, "Failed to find real read function: %s\n", dlerror());
            dlclose(handle);
            return;
        }
       *correct_addr = myread;
    }else if (strcmp(replace_func_name, "write") == 0) {
        real_write = dlsym(handle, replace_func_name);
        if (!real_write) {
            fprintf(stderr, "Failed to find real write function: %s\n", dlerror());
            dlclose(handle);
            return;
        }
       *correct_addr = mywrite;
    }else if (strcmp(replace_func_name, "connect") == 0) {
        real_connect = dlsym(handle, replace_func_name);
        if (!real_connect) {
            fprintf(stderr, "Failed to find real connect function: %s\n", dlerror());
            dlclose(handle);
            return;
        }
       *correct_addr = myconnect;
    }else if (strcmp(replace_func_name, "getaddrinfo") == 0) {
        real_getaddrinfo = dlsym(handle, replace_func_name);
        if (!real_getaddrinfo) {
            fprintf(stderr, "Failed to find real getaddrinfo function: %s\n", dlerror());
            dlclose(handle);
            return;
        }
       *correct_addr = mygetaddrinfo;
    }else if (strcmp(replace_func_name, "system") == 0) {
        real_system = dlsym(handle, replace_func_name);
        if (!real_system) {
            fprintf(stderr, "Failed to find real system function: %s\n", dlerror());
            dlclose(handle);
            return;
        }
       *correct_addr = mysystem;
    }

    // 关闭库
    dlclose(handle);

}

int mysystem(const char *command){
    dprintf(atoi(getenv("LOGGER_FD")), "[logger] system(\"%s\")\n", command);

    int ret_val = real_system(command);
    // unsetenv("LD_PRELOAD");
    return ret_val;
}

int mygetaddrinfo(const char *restrict node, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res){
    int is_block = isBlackList("getaddrinfo", node);

    // int ret_val = real_getaddrinfo(node, service, hints, res);
    node_name = node;
    int ret_val;
    if(is_block){
        ret_val = EAI_NONAME;
    }else{
        ret_val = real_getaddrinfo(node, service, hints, res);
    }

    dprintf(atoi(getenv("LOGGER_FD")), "[logger] getaddrinfo(\"%s\", \"%s\", %p, %p) = %d\n", node, service, hints, res, ret_val);

    return ret_val;
}

int myconnect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    char ip_str[INET_ADDRSTRLEN];
    uint16_t port;
    struct sockaddr_in *addr_in = (struct sockaddr_in*)addr;
    inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, INET_ADDRSTRLEN);
    port = ntohs(addr_in->sin_port);
    // printf("The IPv4 address is: %s, port is: %d\n", ip_str, port);
    // sprintf(node_name + strlen(node_name), ":%d", port);

    if(strstr(node_name, ":") == NULL) {
        char *tmp = node_name;
        sprintf(node_name , "%s:%d", tmp, port);
    }

    int is_block = isBlackList("connect", node_name);
    int ret_val;

    if(is_block){
        errno = ECONNREFUSED;
        ret_val = -1;
    }else{
        ret_val = real_connect(sockfd, addr, addrlen);
    }
    dprintf(atoi(getenv("LOGGER_FD")), "[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, ip_str, addrlen, ret_val);

    return ret_val;
}

ssize_t mywrite(int fd, void *buf, size_t count){
    ssize_t num_write = real_write(fd, buf, count);
    dprintf(atoi(getenv("LOGGER_FD")), "[logger] write(%d, %p, %ld) = %ld\n", fd, buf, count, num_write);

    int pid = getpid();
    char* filename = NULL;
    asprintf(&filename, "%d-%d-write.log", pid, fd);
    FILE* log_file =  fopen(filename, "a");
    fwrite(buf, 1, num_write, log_file);
    fflush(log_file);

    return num_write;
}

ssize_t myread(int fd, void *buf, size_t count){
    char* filter = getReadFilter();

    int pid = getpid();
    char* filename = NULL;
    size_t n = strlen(filter);
    char tmp_buf[n];
    asprintf(&filename, "%d-%d-read.log", pid, fd);
    FILE* log_file =  fopen(filename, "a");
    if (log_file == NULL) {
        // Error handling for fopen failure
        free(filename);
        return -1;
    }

    ssize_t num_read = real_read(fd, buf, count);
    int is_block = isBlackList("read", buf);
    if (is_block) {
        close(fd);
        fclose(log_file);
        num_read = -1;
        errno = EIO;
        dprintf(atoi(getenv("LOGGER_FD")), "[logger] read(%d, %p, %ld) = %ld\n", fd, buf, count, num_read);

        return num_read;
    }


    fseek(log_file, -n, SEEK_END);
    fread(tmp_buf, sizeof(char), n, log_file);

    // tmp_buf[n] = '\0';  // 在字元陣列最後加上 null 結尾字元，以便將其當作字串使用

    // char * buffer = (char*) malloc(n + num_read + 1);
    // memset(buffer, '\0', n + num_read + 1);
    // strcpy(buffer, tmp_buf);
    // strncat(buffer, read_buf, num_read);

    char * buffer = (char*) malloc(2*n + 1);
    memset(buffer, '\0', 2*n + 1);
    strcpy(buffer, tmp_buf);
    // buf = (void*) buffer + strlen(tmp_buf);
    memcpy(buffer+ strlen(tmp_buf), buf, n);


    // printf("合併後的字串是： \"%s\", len: %ld\n", buffer, strlen(buffer));
    if (strstr(buffer, filter) != NULL) {
        // printf("New string contains blacklisted keyword: %s\n", filter);

        free(buffer);
        free(filename);
        fclose(log_file);
        close(fd);
        num_read = -1;
        errno = EIO;
        dprintf(atoi(getenv("LOGGER_FD")), "[logger] read(%d, %p, %ld) = %ld\n", fd, buf, count, num_read);

        return num_read;
    }

    fseek(log_file, 0, SEEK_END);
    fwrite(buf, 1, num_read, log_file);
    fflush(log_file);

    free(buffer);
    free(filename);
    fclose(log_file);
    dprintf(atoi(getenv("LOGGER_FD")), "[logger] read(%d, %p, %ld) = %ld\n", fd, buf, count, num_read);

    return num_read;
}

int myopen(const char *path, int flags, ...) {
    char *r_path;
    if(realpath(path, r_path) == NULL){
        perror("realpath");
    }
    int is_block = isBlackList("open", r_path);
    int ret_val;

    if(is_block){
        errno = EACCES;
        ret_val = -1;
    }else{
        // 调用真正的open函数
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        ret_val = real_open(path, flags, mode);
    }
    dprintf(atoi(getenv("LOGGER_FD")), "[logger] open(\"%s\", 0, 0) = %d\n", path, ret_val);
    return ret_val;
}

// Define your own version of __libc_start_main
int __libc_start_main(int (*main)(int, char**, char**), 
                        int argc, 
                        char* argv[],
                        void (*init)(void), 
                        void (*fini)(void),
                        void (*rtld_fini)(void), 
                        void* stack_end) {
    input_command = argv[0];
    char path[PATH_MAX];
    get_executable_path(path, sizeof(path));
    int j=2;
    if(argv[0][0]=='.' && argv[0][1] == '/'){
        for(int i=strlen(path); i<strlen(path)+strlen(argv[0])-1; i++){
            // printf("i: %d", i)
            path[i] = argv[0][j];
            j++;
        }
        input_command = path;
    }else{
        strcat(path, argv[0]);
    }

    // printf ("this program is in the directory %s\n", path);

    char *filename = path;
    // printf("%s\n",filename);
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    // 读取 ELF 文件头
    Elf64_Ehdr elf_header; //header
    if (fread(&elf_header, sizeof(Elf64_Ehdr), 1, fp) != 1) {
        fprintf(stderr, "Failed to read ELF header from file %s\n", filename);
        exit(EXIT_FAILURE);
    }
    // printf("elf\n");

    // 计算重定位表的地址和大小
    Elf64_Shdr *shdr_table = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr) * elf_header.e_shnum);
    if (!shdr_table) {
        fprintf(stderr, "Failed to allocate memory for section header table\n");
        exit(EXIT_FAILURE);
    }

    fseek(fp, elf_header.e_shoff, SEEK_SET);// section header start 
    if (fread(shdr_table, sizeof(Elf64_Shdr), elf_header.e_shnum, fp) != elf_header.e_shnum) {
        fprintf(stderr, "Failed to read section header table from file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    Elf64_Shdr *rela_plt_hdr = NULL;
    Elf64_Shdr *symtab_hdr = NULL;
    Elf64_Shdr *strtab_hdr = NULL;

    // 找到 .rela.plt 节
    int str_count=0;
    for (int i = 0; i < elf_header.e_shnum; i++) {
        // printf("header %d \n",shdr_table[i].sh_type);
        if (shdr_table[i].sh_type == SHT_RELA ) {
            // printf(".rela.plt\n");
            rela_plt_hdr = &shdr_table[i];
            // break;
        }
        else if (shdr_table[i].sh_type == SHT_DYNSYM) {
            // printf("dyn.sym\n");
            symtab_hdr = &shdr_table[i];
        }
        else if (shdr_table[i].sh_type == SHT_STRTAB && str_count==0) {
            // printf("strtab\n");
            strtab_hdr = &shdr_table[i];
            str_count=1;
        }
        // printf("%d\n",i);
    }

    if (!rela_plt_hdr) {
        fprintf(stderr, "Failed to find .rela.plt section in file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    if (!symtab_hdr) {
        fprintf(stderr, "Failed to find symbol table section in file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    if (!strtab_hdr) {
        fprintf(stderr, "Failed to find string table section in file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    // 读取 .rela.plt 节中的内容
    fseek(fp, rela_plt_hdr->sh_offset, SEEK_SET);
    size_t num_relocations = rela_plt_hdr->sh_size / rela_plt_hdr->sh_entsize;
    Elf64_Rela *relocations = (Elf64_Rela *)malloc(sizeof(Elf64_Rela) * (num_relocations));
    if (!relocations) {
        fprintf(stderr, "Failed to allocate memory for relocations\n");
        exit(EXIT_FAILURE);
    }

    if (fread(relocations, rela_plt_hdr->sh_entsize, num_relocations, fp) != num_relocations) {
        fprintf(stderr, "Failed to read relocations from file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    // 读取符号表和字符串表
    fseek(fp, symtab_hdr->sh_offset, SEEK_SET);
    size_t num_symbols = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
    Elf64_Sym *symbols = (Elf64_Sym *)malloc(sizeof(Elf64_Sym) * num_symbols);
    if (!symbols) {
        fprintf(stderr, "Failed to allocate memory for symbols\n");
        exit(EXIT_FAILURE);
    }

    if (fread(symbols, symtab_hdr->sh_entsize, num_symbols, fp) != num_symbols) {
        fprintf(stderr, "Failed to read symbols from file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    fseek(fp, strtab_hdr->sh_offset, SEEK_SET);
    char *strtab = (char *)malloc(strtab_hdr->sh_size);
    if (!strtab) {
        fprintf(stderr, "Failed to allocate memory for string table\n");
        exit(EXIT_FAILURE);
    }

    if (fread(strtab, 1, strtab_hdr->sh_size, fp) != strtab_hdr->sh_size) {
        fprintf(stderr, "Failed to read string table from file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    
    // printf("real path: %s\n",path);

    long min = 0, max = 0, index = 0;
    int fd, sz;
    char _buf[16384], *s = _buf, *line, *saveptr;
    if(max != 0) return;
    if((fd = open("/proc/self/maps", O_RDONLY)) < 0) perror("get_base/open");
    if((sz = read(fd, _buf, sizeof(_buf)-1)) < 0) perror("get_base/read");
    _buf[sz] = 0;
    close(fd);
    while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { 
        s = NULL;
        // printf("%s\n",filename);
        if(strstr(line, input_command) != NULL) {
            if(sscanf(line, "%lx-%lx ", &min, &max) != 2) perror("get_base/main");
            //printf("%lx-%lx \n\n", main_min, main_max);
            record[index] = min;
            // printf("%lx\n", record[index]);
            index++;
        }
    }

    // 在重定位表中查找 open 函数的符号
    for (int i = 0; i < num_relocations; i++) {
        Elf64_Rela *rela = &relocations[i];
        // printf("%d,%ld,%ld\n",i,ELF64_R_TYPE(rela->r_info),R_X86_64_JUMP_SLOT);
        if (ELF64_R_TYPE(rela->r_info) == R_X86_64_JUMP_SLOT) {
            Elf64_Sym *sym = &symbols[ELF64_R_SYM(rela->r_info)];
            char *symname = &strtab[sym->st_name];

            // printf("%s %lx st_name:%d\n",symname,rela->r_offset,sym->st_name);
            if (strcmp(symname, "read") == 0) {
                // printf("Found read at index %d, offset 0x%lx\n", i, rela->r_offset);
                cur_command = "read";
                Redirect(rela->r_offset, "read");

            }else if(strcmp(symname,"open")==0){
                // printf("Found open at index %d, offset 0x%lx\n", i, rela->r_offset);
                cur_command = "open";
                Redirect(rela->r_offset, "open");

            }else if(strcmp(symname,"write")==0){
                // printf("Found write at index %d, offset 0x%lx\n", i, rela->r_offset);
                cur_command = "write";
                Redirect(rela->r_offset, "write");

            }else if(strcmp(symname,"connect")==0){
                // printf("Found connect at index %d, offset 0x%lx\n", i, rela->r_offset);
                cur_command = "connect";
                Redirect(rela->r_offset, "connect");

            }else if(strcmp(symname,"getaddrinfo")==0){
                // printf("Found getaddrinfo at index %d, offset 0x%lx\n", i, rela->r_offset);
                cur_command = "getaddrinfo";
                Redirect(rela->r_offset, "getaddrinfo");

            }else if(strcmp(symname,"system")==0){
                // printf("Found system at index %d, offset 0x%lx\n", i, rela->r_offset);
                cur_command = "system";
                Redirect(rela->r_offset, "system");

            }
        }
    }

    fclose(fp);
    free(relocations);
    free(symbols);
    free(strtab);
    /* read elf end*/

    void *libc_handle;
    int (*real_libc_start_main)(int (*)(int, char **, char **), int, char *[], void (*)(void), void (*)(void), void (*)(void), void *);
    // Get a reference to the real __libc_start_main function
    libc_handle = dlopen("libc.so.6", RTLD_LAZY);
    if (!libc_handle) {
        fprintf(stderr, "Failed to load libc.so.6: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }

    /* get a pointer to the real __libc_start_main function */
    real_libc_start_main = dlsym(libc_handle, "__libc_start_main");

    // Call the real __libc_start_main function to start the program
    return real_libc_start_main(main, argc, argv, init, fini, rtld_fini, stack_end);
}