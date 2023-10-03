CC=gcc
CFLAGS= -Wall -g -I.
DEPS = elf-parser.h
OBJ = elf-parser.o 

elf-parser.o: elf-parser.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

sandbox.so:  sandbox.c $(OBJ)
	$(CC) -ldl -shared -fPIC -o $@ $^

all:
	make elf-parser.o
	make sandbox.so

clean:
	rm -rf *.so 
	rm -rf *.o 
	rm -rf *.html.*
	rm -rf *.html
	rm -rf *.log

test1:
	./launcher ./sandbox.so config.txt cat /etc/passwd

test2:
	./launcher ./sandbox.so config.txt cat /etc/hosts

test3:
	./launcher ./sandbox.so config.txt cat /etc/ssl/certs/Amazon_Root_CA_1.pem

test5:
	./launcher ./sandbox.so config.txt wget http://google.com -t 1

test6:
	./launcher ./sandbox.so config.txt wget https://www.nycu.edu.tw -t 1

test7:
	./launcher ./sandbox.so config.txt wget http://www.google.com -q -t 1

test8:
	./launcher ./sandbox.so config.txt python3 -c 'import os;os.system("wget http://www.google.com -q -t 1")'
	