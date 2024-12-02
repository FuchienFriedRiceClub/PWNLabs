# simple makefile template
CC=gcc
CFLAG=-g -save-temps -z noexecstack -Wno-stringop-overflow
# compiler options
LDFLAG= -fno-PIE -no-pie -fno-PIC
# link options
LIB_DIR=
LIB=
BASE_DIR=
INC_DIR=
INC=

SRC=main.c
OBJ_DIR=./obj
NAME=brop_example
OBJ=$(patsubst %.c, $(OBJ_DIR)/%.o, $(SRC))
# ar x /usr/local/glibc-2.31/lib/libc_nonshared.a
OBJ+=elf-init.oS
# $(patsubst replaced value, replace value, files list)

all: ObjDirCreate $(NAME)

ObjDirCreate:
	mkdir -p $(OBJ_DIR)

$(NAME): $(OBJ)
	$(CC) $^ -o $@ $(CFLAG) $(INC) $(LIB) $(LDFLAG)

$(OBJ_DIR)/%.o: %.c
	$(CC) -c $^ -o $@ $(CFLAG) $(INC)

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR) $(NAME) *.out

# 1 : 2
# $@: $^
