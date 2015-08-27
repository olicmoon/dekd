CC = g++

TARGET_DIR=../obj/
TARGET=$(TARGET_DIR)ndc

LIBS = 
CFLAGS = -O2 -Wall -fPIC -std=c++0x -g -I../include/
LDFLAGS = -fPIC -L$(TARGET_DIR) -lknox_crypto -lknox_utils -lpthread -lcrypto 

OBJS := ndc.o DekClient.o socket_local_client.o

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

all: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

