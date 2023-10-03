
all: 
	gcc -fno-stack-protector -masm=intel -O3 -S sort.c 
	# yasm -f elf64 -DYASM -D__x86_64__ -DPIC sort.s -o sort.o
	# ld -m elf_x86_64 -o sort sort.o

