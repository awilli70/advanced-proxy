src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc
LDFLAGS = -lpthread -L/usr/local/ssl/lib -g

a.out: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS) -lnsl -lssl -lcrypto

mac: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out
