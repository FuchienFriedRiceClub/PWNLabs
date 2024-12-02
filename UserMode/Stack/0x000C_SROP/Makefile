# simple makefile template
CC=gcc
CFLAG=-g -save-temps -fno-stack-protector -z noexecstack -z relro -z now -no-pie
# compiler options
LDFLAG=
# link options
LIB_DIR=
LIB=
BASE_DIR=
INC_DIR=
INC=

NAME=srop_example

all: $(NAME)

$(NAME): $(OBJ)
	as -o main.o main.S
	ld -s -o $(NAME) main.o

.PHONY: clean
clean:
	rm -rf $(NAME) *.o

# 1 : 2
# $@: $^
