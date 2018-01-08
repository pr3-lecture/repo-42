CC = gcc
COMPILER_OPTIONS = -Wall

.PHONY: all clean
all: encrypt decrypt test
clean: rm -f encrypt decrypt main.o crypto.o test

main.o: main.c
	$(CC) $(COMPILER_OPTIONS) -c $^

crypto.o: crypto.c
	$(CC) $(COMPILER_OPTIONS) -c $^

encrypt: main.o crypto.o
	$(CC) -o encrypt $^

decrypt: main.o crypto.o
	$(CC) -o decrypt $^

test: test.o crypto.o
	$(CC) -o test $^
