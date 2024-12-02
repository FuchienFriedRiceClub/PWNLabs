# simple makefile template
CC=gcc
CFLAG=-g -save-temps -Wno-stringop-overflow -Wno-stringop-overread -fno-stack-protector -z noexecstack -no-pie
# compiler options
LDFLAG=
# link options
LIB_DIR=
LIB=
BASE_DIR=
INC_DIR=
INC=

SRC=main.c
OBJ_DIR=./obj
NAME=ret2dlresolve_example
OBJ=$(patsubst %.c, $(OBJ_DIR)/%.o, $(SRC))
# ar x /usr/local/glibc-2.31/lib/libc_nonshared.a
OBJ+=elf-init.oS
# $(patsubst replaced value, replace value, files list)

all: NoRelRoBuild PartialRelRoBuild

NoRelRoBuild: ObjDirCreate $(NAME)_NoRelRO
PartialRelRoBuild: ObjDirCreate $(NAME)_PartialRelRO

ObjDirCreate:
	mkdir -p $(OBJ_DIR)

$(NAME)_NoRelRO: $(OBJ)
	$(CC) $^ -o $@ $(CFLAG) $(INC) $(LIB) $(LDFLAG) -z norelro

$(NAME)_PartialRelRO: $(OBJ)
	$(CC) $^ -o $@ $(CFLAG) $(INC) $(LIB) $(LDFLAG) -z lazy

$(OBJ_DIR)/%.o: %.c
	$(CC) -c $^ -o $@ $(CFLAG) $(INC)

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR)* $(NAME)*

# 1 : 2
# $@: $^
