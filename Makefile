
# ACHTUNG unbedingt TABS benutzen beim einrücken

CC = g++
#CFLAGS = -ggdb -pthread
CFLAGS = -Wall -O3 -std=c++14 -pthread -ffunction-sections -fdata-sections
TARGET = libsocketlib.a

OBJ = $(patsubst %.cpp,%.o,$(wildcard *.cpp))	#OBJ = SslSocket.o StdSocket.o OpenSSLWraper.o

$(TARGET): $(OBJ)
	ar rs $@ $^

%.o: %.cpp
	$(CC) $(CFLAGS) $(INC_PATH) -c $<

clean:
	rm -f $(TARGET) $(OBJ) *~

