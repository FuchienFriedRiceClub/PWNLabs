# simple makefile template
CC=gcc
CXX=g++
CFLAG=-g -save-temps -fstack-protector
# compiler options
LDFLAG=-no-pie
# link options
LIB_DIR=
LIB=
BASE_DIR=
INC_DIR=
INC=

SRC_A=main.c
OBJ_DIR_A=./obj_A
NAME_A=type_confusion_example4c
OBJ_A=$(patsubst %.c, $(OBJ_DIR_A)/%.o, $(SRC_A))

SRC_B=main.cpp
OBJ_DIR_B=./obj_B
NAME_B=type_confusion_example4cpp
OBJ_B=$(patsubst %.cpp, $(OBJ_DIR_B)/%.o, $(SRC_B))
# $(patsubst replaced value, replace value, files list)

all: ObjDirCreate $(NAME_A) $(NAME_B)

ObjDirCreate:
	mkdir -p $(OBJ_DIR_A) $(OBJ_DIR_B)

$(NAME_A): $(OBJ_A)
	$(CC) $^ -o $@ $(CFLAG) $(INC) $(LIB) $(LDFLAG)

$(NAME_B): $(OBJ_B)
	$(CXX) $^ -o $@ $(CFLAG) $(INC) $(LIB) $(LDFLAG)

$(OBJ_DIR_A)/%.o: %.c
	$(CC) -c $^ -o $@ $(CFLAG) $(INC)

$(OBJ_DIR_B)/%.o: %.cpp
	$(CXX) -c $^ -o $@ $(CFLAG) $(INC)

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR_A) $(OBJ_DIR_B) $(NAME_A) $(NAME_B)

# 1 : 2
# $@: $^
