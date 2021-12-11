# Makefile
# 
# Simple SSL Echo Server
# 15-441 Networks, Fall 2002
# 
# Justin Weisz (jweisz@andrew.cmu.edu)
# 
# Created: 07/24/02


CC = gcc -Wall -I/usr/local/include/

server = echo_server.o ssl_common.o
client = echo_client.o ssl_common.o


all : echo_server echo_client


echo_server : $(server)
	$(CC) -lssl $(server) -o echo_server -lcrypto

echo_client : $(client)
	$(CC) -lssl $(client) -o echo_client -lcrypto


echo_server.o : 
	$(CC) -c echo_server.c

echo_client.o : 
	$(CC) -c echo_client.c

ssl_common.o : 
	$(CC) -c ssl_common.c


.PHONY : clean
clean : 
	-rm -f echo_server echo_client *.o core
