#include<stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h> // for close
#include <sys/mman.h>
#include <netdb.h>
#include <dlfcn.h>
#include <string.h>
#include <stdarg.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>


#include "elf-parser.h"

#define TARGET_LIBC  "libc.so.6"
#define LINE_MAX 128
#define LINE_CHAR_MAX 1024

typedef struct blacklist{
	int how_many_line;
	char ban[LINE_MAX][LINE_CHAR_MAX];
}BlackList;

//
// Original API function address
//
static int (*original_libc_start_main)( int (*main)(int, char ** argv, char **), int argc, char ** ubp_av, void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void (*stack_end) ) = NULL;
static int (*original_open)(const char *path, int oflag, ...) = NULL;
static ssize_t (*original_write)(int fildes, const void *buf, size_t nbyte) = NULL;
static ssize_t (*original_read)(int fildes, void *buf, size_t nbyte) = NULL;
static int (*original_connect)(int socket, const struct sockaddr *address,socklen_t address_len) = NULL;
static int (*original_getaddrinfo)(const char  *nodename, const char *servname, const struct addrinfo *hints, struct addrinfo **res) = NULL;
static int (*original_system)(const char *command) = NULL;

//
// My function
//
int _my_open(const char *path, int oflag, ...);
ssize_t _my_write(int fildes, const void *buf, size_t nbyte);
ssize_t _my_read(int fildes, void *buf, size_t nbyte);
int _my_connect(int socket, const struct sockaddr *address,socklen_t address_len);
int _my_getaddrinfo(const char  *nodename, const char *servname, const struct addrinfo *hints, struct addrinfo **res);
int _my_system(const char *command);

//
// BlackList
//
BlackList black_open;
BlackList black_write;
BlackList black_read;
BlackList black_connect;
BlackList black_getaddrinfo;
BlackList black_system;

int __libc_start_main(int *(main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)){

	//
    // save original libc_start_main    
    //
	char *error;
    void *handle =  dlopen(TARGET_LIBC, RTLD_LAZY);
    original_libc_start_main = dlsym(handle, "__libc_start_main");
    if (original_libc_start_main == NULL)  {
        fprintf(stderr, "%s\n", error);
        exit(EXIT_FAILURE);
    }

	//
    // find GOT start adress and do mprotect
    //
	long int basic_address;
    static long int main_min = 0, main_max = 0;
    int fd, sz;
	char buf[16384], *s = buf, *line, *saveptr;
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("get_base/open");
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("get_base/read");
	buf[sz] = 0;
	close(fd);

    char target_command[128];
    readlink("/proc/self/exe" , target_command , 128);

    int count = 1;
	while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { s = NULL;
        if(count == 5) break;
		if(strstr(line, target_command) != NULL) {
			if(sscanf(line, "%lx-%lx ", &main_min, &main_max) != 2) errquit("get_base/main");
            if(count == 1) basic_address = main_min;
            // printf("%lx-%lx\n",main_min,main_max);
		}
        count++;
	}
    // printf("%lx-%lx\n",main_min,main_max);
    if (mprotect(main_min , main_max-main_min , PROT_WRITE)) {
        perror("Couldn’t mprotect");
        exit(errno);
    }

	//
    //find GOT Offset
    //
	Function_INFO list[6];
	list[0].function_name = "open";
	list[1].function_name = "write";
	list[2].function_name = "read";
	list[3].function_name = "connect";
	list[4].function_name = "getaddrinfo";
	list[5].function_name = "system";

    int32_t fd2;
	if((fd2 = open(target_command, O_RDONLY | O_SYNC)) < 0) errquit("target command open failed!!");

	Elf64_Ehdr eh64;	/* elf-header is fixed size */
	Elf64_Shdr* sh_tbl;	/* section-header table is variable size */
	read_elf_header64(fd2, &eh64);
	if(!is_ELF64(eh64)) {
		return 0;
	}

	sh_tbl = malloc(eh64.e_shentsize * eh64.e_shnum);
	if(!sh_tbl) {
		printf("Failed to allocate %d bytes\n",
				(eh64.e_shentsize * eh64.e_shnum));
	}
	read_section_header_table64(fd2, eh64, sh_tbl);
	print_symbols64(fd2, eh64, sh_tbl , &list);
	print_rela64(fd2, eh64, sh_tbl , &list);

	//
	// catch config.txt to blacklist
	//
	FILE *fp;
    char *line1 = NULL;
    size_t len = 0;
    ssize_t read;
    char *config_file = getenv("SANDBOX_CONFIG");
    fp = fopen(config_file, "r");
    if (fp == NULL)
    {
        printf("File Not Found");
        return 0;
    }
    int state_case = 0;
    while ((read = getline(&line1, &len, fp) != -1))
    {
        char *line = strtok(line1 , "\n");
        if(line == NULL) continue;

        if(strcmp(line , "END open-blacklist") == 0) state_case = 0;
        else if(strcmp(line , "END write-blacklist") == 0) state_case = 0;
        else if(strcmp(line , "END read-blacklist") == 0) state_case = 0;
        else if(strcmp(line , "END connect-blacklist") == 0) state_case = 0;
        else if(strcmp(line , "END getaddrinfo-blacklist") == 0) state_case = 0;
        else if(strcmp(line , "END system-blacklist") == 0) state_case = 0;

        int index = 0;
        switch(state_case){
            case 1:
                index = black_open.how_many_line;
                strcpy(black_open.ban[index],line); 
                black_open.how_many_line++;
                break;
            case 2:
                index = black_write.how_many_line;
                strcpy(black_write.ban[index],line); 
                black_write.how_many_line++;
                break;
            case 3:
                index = black_read.how_many_line;
                strcpy(black_read.ban[index],line); 
                black_read.how_many_line++;
                break;
            case 4:
                index = black_connect.how_many_line;
                strcpy(black_connect.ban[index],line); 
                black_connect.how_many_line++;
                break;
            case 5:
                index = black_getaddrinfo.how_many_line;
                strcpy(black_getaddrinfo.ban[index],line); 
                black_getaddrinfo.how_many_line++;
                break;
            case 6:
                index = black_system.how_many_line;
                strcpy(black_system.ban[index],line); 
                black_system.how_many_line++;
                break;

        }
        if(strcmp(line , "BEGIN open-blacklist") == 0) state_case = 1;
        else if(strcmp(line , "BEGIN write-blacklist") == 0) state_case = 2;
        else if(strcmp(line , "BEGIN read-blacklist") == 0) state_case = 3;
        else if(strcmp(line , "BEGIN connect-blacklist") == 0) state_case = 4;
        else if(strcmp(line , "BEGIN getaddrinfo-blacklist") == 0) state_case = 5;
        else if(strcmp(line , "BEGIN system-blacklist") == 0) state_case = 6;  
    }
    fclose(fp);

    // test
    // for(int i = 0 ; i < black_open.how_many_line ; i++) printf("%s\n" , black_open.ban[i]);
    // for(int i = 0 ; i < black_write.how_many_line ; i++) printf("%s\n" , black_write.ban[i]);
    // for(int i = 0 ; i < black_read.how_many_line ; i++) printf("%s\n" , black_read.ban[i]);
    // for(int i = 0 ; i < black_connect.how_many_line ; i++) printf("%s\n" , black_connect.ban[i]);
    // for(int i = 0 ; i < black_getaddrinfo.how_many_line ; i++) printf("%s\n" , black_getaddrinfo.ban[i]);
    // for(int i = 0 ; i < black_system.how_many_line ; i++) printf("%s\n" , black_system.ban[i]);

	//
	//hijack API
	//
	original_open = dlsym(handle , "open");
	original_write = dlsym(handle , "write");
	original_read = dlsym(handle , "read");
	original_connect = dlsym(handle , "connect");
	original_getaddrinfo = dlsym(handle , "getaddrinfo");
	original_system = dlsym(handle , "system");

	long int my_open_addr = &_my_open;
	long int my_write_addr = &_my_write;
	long int my_read_addr = &_my_read;
	long int my_connect_addr = &_my_connect;
	long int my_getaddrinfo_addr = &_my_getaddrinfo;
	long int my_system_addr = &_my_system;

	// printf("This is my_open addr : %p\n" , _my_open);
	// printf("This is my_open addr : %lx\n" , my_open_addr);

	long int *got_pointer;
	for(int i = 0 ; i < 6 ; i++){
		if(list[i].GOT_Offset !=0) got_pointer =  basic_address + list[i].GOT_Offset;
		else continue;
		if(i==0) *got_pointer =  my_open_addr;
		if(i==1) *got_pointer =  my_write_addr;
		if(i==2) *got_pointer =  my_read_addr;
		if(i==3) *got_pointer =  my_connect_addr;
		if(i==4) *got_pointer =  my_getaddrinfo_addr;
		if(i==5) *got_pointer =  my_system_addr;
	}
	

    close(fd2);
	dlclose(handle);
	//
    // jump to original libc_start_main
    //
	int return_libc = original_libc_start_main( main, argc, ubp_av, init, fini, rtld_fini, stack_end);
    return return_libc;
}

int _my_open(const char *path, int oflag, ...){
	int fd = atoi(getenv("LOGGER_FD"));
	int return_open = 0;
	int mode = 0;
	//get mode's number

	// avoid symbolic link, we need to find true path
	char true_path[128];
	realpath(path , true_path);
	for(int i = 0 ; i < black_open.how_many_line ; i++){
		if (strcmp(true_path , black_open.ban[i]) == 0){
			return_open = -1;
			errno = EACCES;
		}
	}
	if (return_open==0) return_open = original_open(true_path,oflag);
	dprintf(fd , "[logger] open(%s, %d, %d) = %d\n",true_path,oflag , mode, return_open);
	return return_open;
}

ssize_t _my_write(int fildes, const void *buf, size_t nbyte){
    int return_write = original_write(fildes,buf,nbyte);;
	int fd = atoi(getenv("LOGGER_FD"));

    pid_t pid = getpid();
    char log_name[LINE_MAX];
    // printf("pid : %d, fd : %d\n" , pid , fildes);
    snprintf(log_name,LINE_MAX , "%d-%d-write.log" , pid , fildes);
    // printf("%s\n",log_name);
    FILE *fp;
    if( (fp = fopen(log_name , "a")) == NULL ){
        printf("failed to open!!");
        return -1;
    }
    fprintf(fp , "%s" , buf );
    fclose(fp);

    dprintf(fd , "[logger] write(%d, %p, %ld) = %d\n",fildes ,buf , nbyte, return_write);
	return return_write;
}

ssize_t _my_read(int fildes, void *buf, size_t nbyte){
	int fd = atoi(getenv("LOGGER_FD"));
	int return_read = original_read(fildes , buf , nbyte);
    // get pid and fd to make a file name
    pid_t pid = getpid();
    char log_name[LINE_MAX];
    snprintf(log_name , LINE_MAX , "%d-%d-read.log" , pid , fildes);

    //open file start to read
    char* buffer = (char*) buf;
    char o_buffer[32768];

    snprintf(o_buffer , nbyte+1 , "%s" , buf);
    //read file
    for(int i = 0 ; i < black_read.how_many_line ; i++){
        if(strstr(buffer , black_read.ban[i]) !=NULL){
            errno = EIO;
			return_read = -1;
            close(fildes);
            break;
        }
        else{
            FILE *fp;
            if( (fp = fopen(log_name , "r")) != NULL ){
                fseek(fp , 0 , SEEK_END);
                long file_len = ftell(fp) ;
                fseek(fp , 0 , SEEK_SET);
                char* file_content = malloc(file_len + strlen(buffer) + 1);
                // printf("file length : %ld\n",file_len);
                // printf("buffer length : %ld\n",strlen(buffer));
                fread(file_content , file_len , 1 , fp);
                strcpy(file_content+file_len , buffer);
                if(strstr(file_content , black_read.ban[i]) !=NULL){
                    errno = EIO;
                    return_read = -1;
                    close(fildes);
                    break;
                }
                fclose(fp);
                free(file_content);
            }
        }
    }
    if(return_read!=-1 && return_read!=0){
        FILE *fp;
        if( (fp = fopen(log_name , "a")) == NULL ){
            printf("failed to open!!");
            return -1;
        }
        fprintf(fp , "%s", o_buffer );
        fclose(fp);
    }
    dprintf(fd , "[logger] read(%d, %p, %ld) = %d\n",fildes ,buf , nbyte, return_read);
	return return_read;
}

int _my_connect(int socket, const struct sockaddr *address,socklen_t address_len){
	int fd = atoi(getenv("LOGGER_FD"));
	int return_connect = 0;
    struct sockaddr_in *sock = (struct sockaddr_in *)address;
    char port[10];
    snprintf( port , 10 ,"%d" , ntohs(sock->sin_port));
    char ip[INET_ADDRSTRLEN];
    snprintf( ip , INET_ADDRSTRLEN,"%s" ,inet_ntoa(sock->sin_addr));

    for(int i = 0 ; i < black_connect.how_many_line ; i++){
        // split the banned ip & port
        char ban_domain_name[LINE_CHAR_MAX];
        snprintf(ban_domain_name , LINE_CHAR_MAX,"%s" , black_connect.ban[i]);
        char *ban_ip_domain = strtok(ban_domain_name , ":");
        char *ban_port_str = strtok(NULL , "");
        // printf("%s:%s\n",ban_ip_domain , ban_port_str);

        struct hostent *hptr;
        struct in_addr **addr_list;
        hptr = gethostbyname(ban_ip_domain);
        char ban_ip[INET_ADDRSTRLEN];
        inet_ntop(hptr->h_addrtype , hptr->h_addr,ban_ip,sizeof(ban_ip));

        addr_list = (struct in_addr **) hptr->h_addr_list;
        for(i = 0; addr_list[i] != NULL; i++) 
        {
            //Return the first one;
            strcpy(ban_ip , inet_ntoa(*addr_list[i]) );
            if (strcmp(ban_ip , ip) == 0 && strcmp(ban_port_str , port) == 0){
                return_connect = -1;
                errno = ECONNREFUSED;
	            dprintf(fd , "[logger] connect(%d, \"%s\", %d) = %d\n",socket,ip , address_len, return_connect);
                return return_connect;
            }
        }
        // printf("%s -> %s\n",ban_ip_domain ,ban_ip);

        // ban_ip is converted from ban_domain_name
		
	}

	if(return_connect==0) return_connect = original_connect(socket , address , address_len);
	dprintf(fd , "[logger] connect(%d, \"%s\", %d) = %d\n",socket,ip , address_len, return_connect);
	return return_connect;	
}

int _my_getaddrinfo(const char  *nodename, const char *servname, const struct addrinfo *hints, struct addrinfo **res){
	int fd = atoi(getenv("LOGGER_FD"));
	int return_getaddrinfo = 0;

	for(int i = 0 ; i < black_getaddrinfo.how_many_line ; i++){
		if (strcmp(nodename , black_getaddrinfo.ban[i]) == 0){
			return_getaddrinfo = EAI_NONAME;
		}
	}
	if (return_getaddrinfo==0) return_getaddrinfo = original_getaddrinfo(nodename , servname , hints , res);
	dprintf(fd , "[logger] getaddrinfo(\"%s\", \"%s\", %p , %p) = %d\n",nodename,servname , hints , res, return_getaddrinfo);
	return return_getaddrinfo;
}

int _my_system(const char *command){
	int fd = atoi(getenv("LOGGER_FD"));
	int return_system , status = 0;
	pid_t pid ;
    return_system = original_system(command);
    dprintf(fd , "[logger] system(%s)\n",command);

	return return_system;

}