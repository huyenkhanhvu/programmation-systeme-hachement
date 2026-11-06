CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lcrypto -pthread

TARGET  = hachement
SRC     = hachement.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o *.cks *.sha

.PHONY: all clean
