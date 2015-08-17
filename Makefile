CC = gcc

SONAME = libknox_utils.so

LIBS = 
CFLAGS = -O2 -Wall -fPIC -g -I./include/
LDFLAGS = -shared -fPIC

OBJS := \
src/FrameworkClient.o \
src/NetlinkEvent.o \
src/SocketClient.o \
src/FrameworkCommand.o \
src/NetlinkListener.o \
src/SocketListener.o \
src/FrameworkListener.o

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

all: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(SONAME)

install:
	cp $(SONAME) ../obj/
	cp $(SONAME) /usr/lib

clean:
	rm -f $(OBJS) $(SONAME)

