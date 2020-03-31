
# ACHTUNG unbedingt TABS benutzen beim einrücken

CC = g++
ifdef $(DEBUG)
CFLAGS = -ggdb -pthread
else
CFLAGS = -Wall -O3 -std=c++14 -pthread -ffunction-sections -fdata-sections
endif
TARGET = libsocketlib.a

OBJ = $(patsubst %.cpp,%.o,$(wildcard *.cpp))	#OBJ = SslSocket.o StdSocket.o OpenSSLWraper.o

$(TARGET): $(OBJ)
	ar rs $@ $^

%.o: %.cpp
	$(CC) $(CFLAGS) $(INC_PATH) -c $<

clean:
	rm -f $(TARGET) $(OBJ) *~

