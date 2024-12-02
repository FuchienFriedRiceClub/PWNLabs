# simple makefile template
CC=gcc
CFLAG=-g -save-temps -fstack-protector -z noexecstack -z relro -z now
# compiler options
LDFLAG=
# link options
LIB_DIR=
LIB=
BASE_DIR=
INC_DIR=
INC=

SRC_A=vuln.c
OBJ_DIR_A=./obj_A
NAME_A=toctou_example4vuln
OBJ_A=$(patsubst %.c, $(OBJ_DIR_A)/%.o, $(SRC_A))

SRC_B=attack.c
OBJ_DIR_B=./obj_B
NAME_B=toctou_example4attack
OBJ_B=$(patsubst %.c, $(OBJ_DIR_B)/%.o, $(SRC_B))
# $(patsubst replaced value, replace value, files list)

all: ObjDirCreate $(NAME_A) $(NAME_B)

ObjDirCreate:
	mkdir -p $(OBJ_DIR_A) $(OBJ_DIR_B)

$(NAME_A): $(OBJ_A)
	$(CC) $^ -o $@ $(CFLAG) $(INC) $(LIB) $(LDFLAG)

$(NAME_B): $(OBJ_B)
	$(CC) $^ -o $@ $(CFLAG) $(INC) $(LIB) $(LDFLAG)

$(OBJ_DIR_A)/%.o: %.c
	$(CC) -c $^ -o $@ $(CFLAG) $(INC)

$(OBJ_DIR_B)/%.o: %.c
	$(CC) -c $^ -o $@ $(CFLAG) $(INC)

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR_A) $(OBJ_DIR_B) $(NAME_A) $(NAME_B)

# 1 : 2
# $@: $^
