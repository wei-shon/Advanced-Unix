#include <elf-parser.h>


void read_elf_header64(int32_t fd, Elf64_Ehdr *elf_header)
{
	assert(elf_header != NULL);
	assert(lseek(fd, (off_t)0, SEEK_SET) == (off_t)0);
	assert(read(fd, (void *)elf_header, sizeof(Elf64_Ehdr)) == sizeof(Elf64_Ehdr));
}


bool is_ELF64(Elf64_Ehdr eh)
{
	/* ELF magic bytes are 0x7f,'E','L','F'
	 * Using  octal escape sequence to represent 0x7f
	 */
	if(!strncmp((char*)eh.e_ident, "\177ELF", 4)) return 1;
	else {
		printf("ELFMAGIC mismatch!\n");
		/* Not ELF file */
		return 0;
	}
}
void read_section_header_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[])
{
	uint32_t i;

	assert(lseek(fd, (off_t)eh.e_shoff, SEEK_SET) == (off_t)eh.e_shoff);

	for(i=0; i<eh.e_shnum; i++) {
		assert(read(fd, (void *)&sh_table[i], eh.e_shentsize)
				== eh.e_shentsize);
	}

}

char * read_section64(int32_t fd, Elf64_Shdr sh)
{
	char* buff = malloc(sh.sh_size);
	if(!buff) {
		printf("%s:Failed to allocate %ldbytes\n",
				__func__, sh.sh_size);
	}

	assert(buff != NULL);
	assert(lseek(fd, (off_t)sh.sh_offset, SEEK_SET) == (off_t)sh.sh_offset);
	assert(read(fd, (void *)buff, sh.sh_size) == sh.sh_size);

	return buff;
}

void print_symbol_table64(int32_t fd, Elf64_Ehdr eh,Elf64_Shdr sh_table[], uint32_t symbol_table, Function_INFO *list){

	char *str_tbl;
	Elf64_Sym* sym_tbl;
	uint32_t i, symbol_count;

	sym_tbl = (Elf64_Sym*)read_section64(fd, sh_table[symbol_table]);

	/* Read linked string-table
	 * Section containing the string table having names of
	 * symbols of this section
	 */
	uint32_t str_tbl_ndx = sh_table[symbol_table].sh_link;
	str_tbl = read_section64(fd, sh_table[str_tbl_ndx]);

	symbol_count = (sh_table[symbol_table].sh_size/sizeof(Elf64_Sym));

	for(i=0; i< symbol_count; i++) {
		char name[100];
		sprintf(name , "%s" , str_tbl + sym_tbl[i].st_name);
		for(int j = 0 ; j < 6 ; j++){
			if(strcmp (list[j].function_name , name)==0){
				list[j].symbol_table_index = i;
			}
		}
	}
}

void print_symbols64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[] ,Function_INFO *list)
{
	for(uint32_t i=0; i<eh.e_shnum; i++) {
		if ((sh_table[i].sh_type==SHT_SYMTAB) || (sh_table[i].sh_type==SHT_DYNSYM)) {
			print_symbol_table64(fd, eh, sh_table, i , list);
		}
	}
	
}
void print_rela_table64(int32_t fd,	Elf64_Ehdr eh, Elf64_Shdr sh_table[], uint32_t rela_table, Function_INFO *list)
{
	Elf64_Rela* rela_tbl;
	uint32_t i, rela_count;

	rela_tbl = (Elf64_Rela*)read_section64(fd, sh_table[rela_table]);
	rela_count = (sh_table[rela_table].sh_size/sizeof(Elf64_Rela));
	for(i=0; i< rela_count; i++) {
		for(int j = 0 ; j < 6 ; j++){
			if(list[j].symbol_table_index!=0 && list[j].symbol_table_index == rela_tbl[i].r_info>>32){
				list[j].GOT_Offset =  rela_tbl[i].r_offset;
				// printf("%llx\n", (rela_tbl[i].r_offset));
			}
		}
	}
}

void print_rela64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],Function_INFO *list)
{
	for(uint32_t i=0; i<eh.e_shnum; i++) {
		if ((sh_table[i].sh_type==SHT_RELA)) {
			print_rela_table64(fd, eh, sh_table, i , list);
		}
	}
}