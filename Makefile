all: icmp_server icmp_client

icmp_server:
	test -d bin || mkdir bin
	gcc src/icmp_server.c -o bin/icmp_server -Wall

icmp_client:
	test -d bin || mkdir bin
	gcc src/icmp_client.c -o bin/icmp_client -lssl -Wall

# vim: noexpandtab
