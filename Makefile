all: bin/icmp_server bin/icmp_client

bin/icmp_server: stage/common.o stage/icmp_server.o
	test -d bin || mkdir bin
	gcc  -Wall stage/icmp_server.o stage/common.o -o bin/icmp_server

bin/icmp_client: stage/common.o stage/icmp_client.o
	test -d bin || mkdir bin
	gcc -lssl -Wall stage/icmp_client.o stage/common.o -o bin/icmp_client

stage/icmp_client.o: src/icmp_client.c
	gcc -Wall -c src/icmp_client.c -o stage/icmp_client.o

stage/icmp_server.o: src/icmp_server.c
	gcc  -Wall -c src/icmp_server.c -o stage/icmp_server.o

stage/common.o: src/common.c src/common.h
	test -d stage || mkdir stage
	gcc -Wall -c src/common.c -o stage/common.o

clean:
	rm -rf stage bin

# vim: noexpandtab
