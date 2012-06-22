#include <linux/netfilter.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>
extern "C" {
	#include "libipq/libipq.h"
}
#include <string>
#include <iostream>
#include <fstream>
#include <bitset>
#include <openssl/aes.h>
#include <sstream>
#include <iomanip>

using namespace std;

#define BUFSIZE 2048

typedef unsigned char u8;
typedef const u8 cu8;

AES_KEY aes_key;

/**
 * Wrapper for the AES_encrypt function
*/
static void encrypt(const char* in, char* out, size_t len, AES_KEY *key) {
	// if (len % 16) exit(1); // not block size multiple
	for (size_t i = 0; i < len; i += 16) {
		AES_encrypt((cu8*)in + i, (u8*)out + i, key);
	}
}
  
/**
 * Used to load AES key from the file
*/    
unsigned char ActualValue(const char *p_input) {
	unsigned char value = 0;

	if (p_input[0] == '1') value += 128;
	if (p_input[1] == '1') value += 64;
	if (p_input[2] == '1') value += 32;
	if (p_input[3] == '1') value += 16;
	if (p_input[4] == '1') value += 8;	
	if (p_input[5] == '1') value += 4;
	if (p_input[6] == '1') value += 2;
	if (p_input[7] == '1') value += 1;

	return value;
}

/**
 * Needed for itoa definition
*/
char *strrev(char *str) {
	char *p1, *p2;

	if (!str || !*str)
		return str;

	for (p1 = str, p2 = str + strlen(str) - 1; p2 > p1; ++p1, --p2) {
		*p1 ^= *p2;
		*p2 ^= *p1;
		*p1 ^= *p2;
	}

	return str;
}

/**
 * Used to get port from TCP header
*/
char *itoa(int n, char *s, int b) {
	static char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	int i=0, sign;
    
	if ((sign = n) < 0)
		n = -n;

	do {
		s[i++] = digits[n % b];
	} while ((n /= b) > 0);

	if (sign < 0)
		s[i++] = '-';
	s[i] = '\0';

	return strrev(s);
}

/**
 * Loads a key into the key structure.
 * Return 1 on success, 0 on failure
 * Params
 *  - des_addr - The IP address we want to talk to
 *  - des_port - The port we want to talk to
*/
int zcc_get_key(unsigned char des_addr[4], int des_port) {
	string l = "/root/cs6250/keys/";
	string ip;
	char *key = NULL;
	char port[5];
	char des[5];
	string key_temp_string, line="";
	int key_length = 0;
	
	itoa(des_port, port, 10);
	itoa((int)des_addr[0], des, 10);
	ip += des;
	ip += ".";
	itoa((int)des_addr[1], des, 10);
	ip += des;
	ip += ".";
	itoa((int)des_addr[2], des, 10);
	ip += des;
	ip += ".";
	itoa((int)des_addr[3], des, 10);
	ip += des;
	
	l += ip;
	l += ":";
  	l += port;
	l += ".txt";

  	const char *location = l.c_str();
  	ifstream file (location);
	int count = 0;
	if (file.is_open()) {
		while (!file.eof()) {
			getline(file, line);
			if (count > 0) {		
				char c = ActualValue(line.c_str());
				key_temp_string += c;
			}
			count++;
		}

		key = (char *)key_temp_string.c_str();
		key_length = key_temp_string.length();
		file.close();
  	} else {
		string command = "/root/cs6250/diffie-hellman/DHClient ";
		command += ip.c_str();
		command += " ";
		command += port;
		command += " 2303 3333";
		system(command.c_str());
	  	ifstream file (location);
  		if (file.is_open()) {
	                while (!file.eof()) {
        	                getline(file, line);
               		         if (count > 0) {
                	                char c = ActualValue(line.c_str());
                       		         key_temp_string += c;
                       		 }
                       		 count++;
                	}

                	key = (char *)key_temp_string.c_str();
                	key_length = key_temp_string.length();
                	file.close();
		} else {
			printf("Could not create key\n");
			return 0;
		}
	}

	unsigned char keybuf[128];
	memset(keybuf, 0, 128);
	memcpy(keybuf, key, (key_length > 128 ? 128 : key_length));

	if (0 != AES_set_encrypt_key(keybuf, 128, &aes_key)) {
		printf("Error setting new key\n");
		return 0;
	}
	
	return 1;


}



/**
 * The function called when we need to encrypt a packet
 * Pull the data from the packet, load the key, encrypt the payload
*/
extern "C" int zcc_encrypt (ipq_packet_msg_t *m) {
	unsigned char src_addr[4], des_addr[4];
	int src_port, des_port;
	unsigned char *packet;
        unsigned int header_length = 0;
	struct tcphdr *tcph;
	unsigned char *payload = NULL;
	int unsigned payload_offset, payload_length;
	int tcphdr_size, iphdr_size;

	struct iphdr *iph = ((struct iphdr *)m->payload);
	memcpy(src_addr, &iph->saddr,4);
	memcpy(des_addr, &iph->daddr,4);

	packet = (unsigned char *)m + sizeof(*m);
	iph = (struct iphdr *)packet;
	header_length += iph->ihl*4;

	tcph = (struct tcphdr *)(packet + header_length);
	header_length += tcph->doff *4;

	payload = packet + header_length;

	tcph = (struct tcphdr *)(m->payload + (iph->ihl << 2));

	iphdr_size = (iph->ihl << 2);
	tcphdr_size = (tcph->doff << 2);

	payload_offset = iphdr_size + tcphdr_size;
	payload_length = (unsigned int) ntohs(iph->tot_len) - (iphdr_size + tcphdr_size);	
	
	src_port = ntohs(tcph->source);
	des_port = ntohs(tcph->dest);

/*	printf("Source Addr: %d.%d.%d.%d:%d\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3], src_port);
	printf("Destin Addr: %d.%d.%d.%d:%d\n", des_addr[0], des_addr[1], des_addr[2], des_addr[3], des_port);
*/
	if (!zcc_get_key(des_addr, des_port)) {
		fprintf(stderr, "We could not get a key for this message.  Aborting encryption\n");
		return 0;
	} 

	char *buf = (char *)malloc(sizeof(char)*payload_length);

	encrypt((const char *)payload, buf, payload_length, &aes_key); 
	memcpy(payload, buf, payload_length*sizeof(char));
	
	return 1;
}
