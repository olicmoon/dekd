CC = gcc

TARGET_DIR=../obj/
TARGET=$(TARGET_DIR)ndc

LIBS = 
CFLAGS = -O2 -Wall -fPIC -g
LDFLAGS = -fPIC

OBJS := ndc.o socket_local_client.o

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

all: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

