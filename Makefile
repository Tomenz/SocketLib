
CC = g++
#CFLAGS = -ggdb -w -m32 -D _DEBUG -D ZLIB_CONST -pthread
CFLAGS = -w -O3 -std=c++14 -m32 -pthread -ffunction-sections -fdata-sections -fomit-frame-pointer
TARGET = libsocketlib.a
INC_PATH = -I .

#OBJ = SslSocket.o StdSocket.o OpenSSLWraper.o
OBJ = $(patsubst %.cpp,%.o,$(wildcard *.cpp))

$(TARGET): $(OBJ)
	ar rs $@ $^

%.o: %.cpp
	$(CC) $(CFLAGS) $(INC_PATH) -c $< 2> error.out

clean:
	rm -f $(TARGET) $(OBJ) *~

