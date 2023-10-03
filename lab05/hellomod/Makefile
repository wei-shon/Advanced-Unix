
obj-m     += kshram.o
ccflags-y += -DEXPORT_SYMTAB

all: hello
	make -C ../dist/modulebuild M=$(PWD) modules

hello: hello.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	rm -f hello
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../dist/newroot/modules
	cp hello kshram.ko ../dist/newroot/modules
