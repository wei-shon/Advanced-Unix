#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <sys/user.h>
#include <time.h>   
struct user_regs_struct go_back_regs ;
void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

int main(int argc, char *argv[]) {
    srand( time(NULL) );
	if(argc < 2) {
		printf( "No execute file\n");
		return -1;
	}

	char* child = argv[1];
    pid_t child_pid = fork();
    if(child_pid < 0){
        printf("Fork is error\n");
		return -1;
    }
    else if(child_pid == 0){
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
        int ret = execlp(argv[1], "", (char *)NULL);
        if(ret < 0) {
            fprintf(stderr, "%s\n", strerror(errno));
            return 1;
        }
    }
    else{
		int wait_status;
		if(waitpid(child_pid, &wait_status, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_EXITKILL);
        printf("main\n");
        struct user_regs_struct regs ;
        int count = 0;
        long long int magic_address;
        long int data1 = 0x31;
        long int data2 = 0x31;
        char* magic_pointer ;
        int first_in = 0;
		while (WIFSTOPPED(wait_status)) {
            if(ptrace(PTRACE_CONT, child_pid, 0, 0) < 0) errquit("ptrace@parent continue4");
		    if(waitpid(child_pid, &wait_status, 0) < 0) errquit("waitpid");
            count++;
            if(count == 1 && first_in==0){
                if(ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) != 0) errquit("ptrace(PTRACE_SINGLESTEP1)");
		        if(waitpid(child_pid, &wait_status, 0) < 0) errquit("waitpid");
                if(ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) != 0) errquit("ptrace(PTRACE_SINGLESTEP2)");
		        if(waitpid(child_pid, &wait_status, 0) < 0) errquit("waitpid");
                if(ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) != 0) errquit("ptrace(PTRACE_SINGLESTEP3)");
		        if(waitpid(child_pid, &wait_status, 0) < 0) errquit("waitpid");
                if(ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) != 0) errquit("ptrace(PTRACE_SINGLESTEP4)");
		        if(waitpid(child_pid, &wait_status, 0) < 0) errquit("waitpid");
                if(ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) != 0) errquit("ptrace(PTRACE_SINGLESTEP4)");
		        if(waitpid(child_pid, &wait_status, 0) < 0) errquit("waitpid");
                if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs) != 0) errquit("ptrace(GETREGS)");
                magic_address = regs.rdi;
                // printf("magic_address : %p\n" , magic_address);
                magic_pointer = (char*)(void*)magic_address;

            }
            else if(count == 3){
                if(first_in==0){
                    if(ptrace(PTRACE_GETREGS, child_pid, 0, &go_back_regs) != 0) errquit("ptrace(GETREGS)");
                    first_in = 1;
                }
                // printf("go_back_regs : rip %p\n" , go_back_regs.rip);
            }
            else if(count == 5){
                if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs) != 0) errquit("ptrace(GETREGS)");
                if(regs.rax==0)return;

                if(ptrace(PTRACE_SETREGS, child_pid, 0, &go_back_regs) != 0) errquit("ptrace(PTRACE_SETREGS)");
                for(int i = 0 ; i < 8 ; i++){
                    double x = (double) rand() / (RAND_MAX + 1.0);
                    if(x < 0.5){
                        data1 = data1<<8;
                        data1+=0x30;
                    }
                    else{
                        data1 = data1<<8;
                        data1+=0x31;
                    }
                }
                for(int i = 0 ; i < 2 ; i++){
                    double x = (double) rand() / (RAND_MAX + 1.0);
                    if(x < 0.5){
                        data2 = data2<<8;
                        data2+=0x30;
                    }
                    else{
                        data2 = data2<<8;
                        data2+=0x31;
                    }
                }
                // printf("\n%llx\n",data1);
                if(ptrace(PTRACE_POKETEXT, child_pid, magic_pointer, data1) != 0) errquit("ptrace(PTRACE_POKETEXT)");
                if(ptrace(PTRACE_POKETEXT, child_pid, magic_pointer+8, data2) != 0) errquit("ptrace(PTRACE_POKETEXT)");   
                count-=2;
                
            }
            
            // long int code = ptrace(PTRACE_PEEKDATA, child_pid,regs.rip , NULL);
            // printf("third\n");
            // printf("Current Instruction: %llx\n", code);
            // printf("third\n");

		}
        // printf("%lld\n" , go_back_regs.rip);
    }

	return 0;
}

