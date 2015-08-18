CC = g++

TARGET_DIR = ../obj/
TARGET = $(TARGET_DIR)dekd

LIBS = 
CFLAGS = -O2 -Wall -fPIC -g -I../include/
LDFLAGS = -fPIC -L$(TARGET_DIR) -lknox_utils -lpthread

OBJS := DekdCmdListener.o DekdCommand.o main.o

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

all: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

