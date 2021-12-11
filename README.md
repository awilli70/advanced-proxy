# Simple Proxy:
## About:
This repository contains an implementation of an advanced HTTP proxy

It:
- Is multiclient
- Has a Shared Proxy Cache
- Has a Content filtering system
- Can operate in a Cooperative Cache mode where multiple nodes are connected using a DHT

## Limitations:

- Max path length of 100 chars
- Max response length of 10mb
- Implements GET and CONNECT only
- DHT max size of 32 nodes
- SSL is not fully implemented due to time constraints

## Usage:

Compile with `make`

Run with `./a.out <ip> <port>`

To run in DHT mode, use the `-multi` flag as follows:
* `./a.out <ip> <port> -multi <ip of existing node> <port of existing node>`

To use content filtering, use the `-cf` flag as follows:

* `./a.out <ip> <port> -cf <content-filtering file>`
* The content filtering file is a list of hostnames to prevent serving a response to

To use SSL (NOT WORKING), use the `-ssl` flag as follows:
* `./a.out <ip> <port> -ssl`


## Files and Dependencies:
Cache.c is a Queue with O(1) access to every element

Dependencies:
- Queue.c (Doubly Linked List with head and tail pointer)
- Hash.c  (Hash Table with chaining)

Proxy.c is the main proxy file

Dependencies:
- server.c is the main file for server behavior (getting client connection fd, reading and writing to client)
- client.c is the main file for client behavior (sending request, retrieving response)
- cache.c
- parse.c (also dependency for Server.c and Client.c) is the main file for C string manipulation and repeated tasks
- error.c implements error handling for threads
- ssl.c contains ssl helper functions

For ssl, key_cert.pem contains self-signed cert and private key

cacert.pem contains a list of trusted certificates from Mozilla, used to verify server certificates

cert.crt is the same as key_cert.pem but without private key
