CFLAGS =  -O2 -Wall -g
LIBS = -lipq -lcrypto -lstdc++

all:
	gcc $(LIBS) $(CFLAGS) -o packet_processor packet_processor.c zccencryption.cpp /usr/lib/libipq.a
	
clean:
	rm -rf packet_processor
