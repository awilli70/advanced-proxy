src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc
LDFLAGS = -lpthread

a.out: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS) -lnsl

mac: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out
