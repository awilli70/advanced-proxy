src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc
LDFLAGS = -lnsl -lpthread

a.out: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out
