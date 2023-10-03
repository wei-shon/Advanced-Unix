#include<stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h> // for close
#include <sys/mman.h>
#include <sys/socket.h>
#include <netdb.h>
#include <dlfcn.h>
#include "elf-parser.h"

#define TARGET_LIBC  "libc.so.6"
#define LINE_MAX 128
#define LINE_CHAR_MAX 1024

typedef struct blacklist{
	int how_many_line = 0;
	char ban[LINE_MAX][LINE_CHAR_MAX];
}BlackList;

//
// BlackList
//
BlackList black_open;
BlackList black_write;
BlackList black_read;
BlackList black_connect;
BlackList black_getaddrinfo;
BlackList black_system;


int main(){
    FILE *fp;
    char *line1 = NULL;
    size_t len = 0;
    ssize_t read;

    // black_open.how_many_line = 0;
    // black_write.how_many_line = 0;
    // black_read.how_many_line = 0;
    // black_connect.how_many_line = 0;
    // black_getaddrinfo.how_many_line = 0;
    // black_system.how_many_line = 0;

    fp = fopen("config.txt", "r");
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
    return 0;
}
    
