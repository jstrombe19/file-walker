CC=gcc
CFLAGS=-g -Wall -std=gnu17
SRC=src
OBJ=obj
SRCS=$(wildcard $(SRC)/*.c)
OBJS=$(patsubst $(OBJ)/%.c, $(OBJ)/%.o, $(SRCS))
BIN=bin
EXE=$(BIN)/file-maker
DATA=processed sample

all: $(EXE) $(SERVER_EXE)

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ -lm 

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	$(RM) -r $(BIN)/* $(OBJ)/* *dSYM $(DATA)