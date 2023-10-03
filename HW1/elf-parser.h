#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <elf.h>

typedef struct function_info{
	char* function_name;
	long long int GOT_Offset;
	int symbol_table_index;
}Function_INFO;

void read_elf_header64(int32_t fd, Elf64_Ehdr *elf_header);
bool is_ELF64(Elf64_Ehdr eh);
void read_section_header_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]);
char * read_section64(int32_t fd, Elf64_Shdr sh);
void print_symbol_table64(int32_t fd,Elf64_Ehdr eh,Elf64_Shdr sh_table[],uint32_t symbol_table ,Function_INFO *list);
void print_symbols64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[] ,Function_INFO *list);
void print_rela_table64(int32_t fd,Elf64_Ehdr eh,Elf64_Shdr sh_table[],uint32_t rela_table ,Function_INFO *list);
void print_rela64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[] ,Function_INFO *list);