
# ACHTUNG unbedingt TABS benutzen beim einrücken

CC = g++
ifeq ($(DEBUG), yes)
CFLAGS = -ggdb -pthread -std=c++14
else
CFLAGS = -Wall -O3 -pthread -std=c++14 -ffunction-sections -fdata-sections
endif
TARGET = libsocketlib.a

OBJ = $(patsubst %.cpp,%.o,$(wildcard *.cpp))	#OBJ = SslSocket.o StdSocket.o OpenSSLWraper.o

$(TARGET): $(OBJ)
	ar rs $@ $^

%.o: %.cpp
	$(CC) $(CFLAGS) $(INC_PATH) -c $<

clean:
	rm -f $(TARGET) $(OBJ) *~

