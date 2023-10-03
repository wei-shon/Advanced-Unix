#include <elf-parser.h>



/* Main entry point of elf-parser */
int32_t main(int32_t argc, char *argv[])
{
	Function_INFO list[6];
	list[0].function_name = "open";
	list[1].function_name = "write";
	list[2].function_name = "read";
	list[3].function_name = "connect";
	list[4].function_name = "getaddrinfo";
	list[5].function_name = "wget";


	int32_t fd;
	Elf32_Ehdr eh;		/* elf-header is fixed size */

	if(argc!=2) {
		printf("Usage: elf-parser <ELF-file>\n");
		return 0;
	}

	fd = open(argv[1], O_RDONLY|O_SYNC);
	if(fd<0) {
		printf("Error %d Unable to open %s\n", fd, argv[1]);
		return 0;
	}

	/* ELF header : at start of file */
	read_elf_header(fd, &eh);
	if(!is_ELF(eh)) {
		return 0;
	}
	if(is64Bit(eh)){
		Elf64_Ehdr eh64;	/* elf-header is fixed size */
		Elf64_Shdr* sh_tbl;	/* section-header table is variable size */

		read_elf_header64(fd, &eh64);
		print_elf_header64(eh64);

		/* Section header table :  */
		sh_tbl = malloc(eh64.e_shentsize * eh64.e_shnum);
		if(!sh_tbl) {
			printf("Failed to allocate %d bytes\n",
					(eh64.e_shentsize * eh64.e_shnum));
		}
		read_section_header_table64(fd, eh64, sh_tbl);
		print_section_headers64(fd, eh64, sh_tbl);

		/* Symbol tables :
		 * sh_tbl[i].sh_type
		 * |`- SHT_SYMTAB
		 *  `- SHT_DYNSYM
		 */
		print_symbols64(fd, eh64, sh_tbl , &list);
		print_rela64(fd, eh64, sh_tbl , &list);
		printf("GOT offset Symbol_index function_name\n");
		for(int i = 0 ; i < 6 ; i++){
			printf("%llx %d %s\n" , list[i].GOT_Offset , list[i].symbol_table_index , list[i].function_name);
		}

	}

	return 0;

}

