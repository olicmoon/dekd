CC = g++

TARGET_DIR = ../obj/
TARGET = $(TARGET_DIR)libknox_crypto.so

LIBS = 
CFLAGS = -O2 -Wall -fPIC -std=c++0x -g -I../include/
LDFLAGS = -fPIC -shared -L$(TARGET_DIR) -g
#LDFLAGS = -fPIC -L$(TARGET_DIR) -lknox_utils -lpthread -lcrypto -g

OBJS := base64.o aesgcm.o ecdh.o sha.o pbkdf.o

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

all: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

