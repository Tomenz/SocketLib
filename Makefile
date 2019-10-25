
# ACHTUNG unbedingt TABS benutzen beim einrücken

CC = g++
CFLAGS = -Wall -O3 -std=c++14 -pthread -ffunction-sections -fdata-sections
TARGET = libsocketlib.a
#INC_PATH = -I ../../openssl-1.0.2f/include

OBJ = $(patsubst %.cpp,%.o,$(wildcard *.cpp))	#OBJ = SslSocket.o StdSocket.o OpenSSLWraper.o

$(TARGET): $(OBJ)
	ar rs $@ $^

%.o: %.cpp
	$(CC) $(CFLAGS) $(INC_PATH) -c $<

clean:
	rm -f $(TARGET) $(OBJ) *~

