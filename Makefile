CC=gcc
LDLIBS=-lssl -lcrypto
CFLAGS=-g -Wall -std=gnu17 -I/usr/include/openssl
LDFLAGS=$(LDLIBS)
SRC=src
OBJ=obj
SRCS=$(wildcard $(SRC)/*.c)
OBJS=$(patsubst $(OBJ)/%.c, $(OBJ)/%.o, $(SRCS))
BIN=bin
EXE=$(BIN)/file-maker
DATA=processed sample

all: $(EXE) $(SERVER_EXE)

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -lm $(OBJS)

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	$(RM) -r $(BIN)/* $(OBJ)/* *dSYM $(DATA)