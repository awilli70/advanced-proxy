# Simple Proxy:
## About:
This repository contains an implementation of a simple HTTP proxy

It:
- Is Single Client
- Is Non-Persistent
- Has a Shared Proxy Cache

## Limitations:

- Max path length of 100 chars
- Max response length of 10mb
- Only implements GET
- Does not handle chunked encoding (will blow up spectacularly)

## Usage:

Compile with `make`

Run with `./a.out <port>`

## Files and Dependencies:
Cache.c is a Queue with O(1) access to every element

Dependencies:
- Queue.c (Doubly Linked List with head and tail pointer)
- Hash.c  (Hash Table with chaining)

Proxy.c is the main proxy file

Dependencies:
- Server.c is the main file for server behavior (getting client connection fd, reading and writing to client)
- Client.c is the main file for client behavior (sending request, retrieving response)
- Cache.c
- Parse.c (also dependency for Server.c and Client.c) is the main file for C string manipulation and repeated tasks

Useful links:
https://www.linuxhowtos.org/C_C++/socket.htm
https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
https://stackoverflow.com/questions/15198834/bind-failed-address-already-in-use

For cache/client:
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Age
