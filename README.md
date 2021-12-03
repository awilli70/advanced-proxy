# Simple Proxy:
## About:
This repository contains an implementation of a simple HTTP proxy

It:
- Is multiclient
- Has a Shared Proxy Cache
- Can operate in a Cooperative Cache mode where multiple nodes are connected using a DHT

## Limitations:

- Max path length of 100 chars
- Max response length of 10mb
- Implements GET and CONNECT only

## Usage:

Compile with `make`

Run with `./a.out <ip> <port> <node ip [OPTIONAL]> <node port[OPTIONAL]>`

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

