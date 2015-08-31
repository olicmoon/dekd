CC = g++

TARGET_DIR = ../obj/
TARGET = $(TARGET_DIR)libknox_utils.so

LIBS = 
CFLAGS = -O2 -Wall -fPIC -std=c++0x -g -I../include/
LDFLAGS = -shared -fPIC -g

OBJS := \
Item.o \
NetlinkEvent.o \
SocketClient.o \
SocketUtil.o \
FrameworkCommand.o \
NetlinkListener.o \
SocketListener.o \
FrameworkListener.o \
DaemonConnector.o \
DaemonEvent.o \
DekClient.o

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

all: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(TARGET)

install:
	sudo cp $(TARGET) /usr/lib

clean:
	rm -f $(OBJS) $(TARGET)

