CC = g++

TARGET_DIR = ../obj/
TARGET = $(TARGET_DIR)dekd

LIBS = 
CFLAGS = -O2 -Wall -fPIC -std=c++0x -ggdb -I../include/
LDFLAGS = -fPIC -L$(TARGET_DIR) -lknox_utils -lknox_crypto -lpthread -lcrypto -lsqlite3 -ggdb 

OBJS := KeyCrypto.o \
storage/KeyStorage.o \
storage/SqlHelper.o \
DekdCmdListener.o \
DekdCommand.o \
main.o

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

all: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

