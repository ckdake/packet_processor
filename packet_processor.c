#include <linux/netfilter.h>
#include <libipq/libipq.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/netfilter_ipv4.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define BUFSIZE 2048

ipq_packet_msg_t *m = NULL;
struct ipq_handle *h= NULL;

int zcc_encrypt(ipq_packet_msg_t*);

static void cleanup() 
{
	if (h) {
		if (m) {
			ipq_set_verdict(h, m->packet_id, NF_DROP, 0, NULL);
			m = NULL;
		}
		ipq_destroy_handle(h);
	}

}

static void die() 
{
	if (h) {
		ipq_perror("passer");
	}
	cleanup();
	exit(1);
}

void sigproc()
{
	cleanup();
	exit(0);
}

void process_packets() 
{
	int status;
	int encrypt_result = 0;
	unsigned char buf[BUFSIZE];

	h = ipq_create_handle(0, PF_INET);
	if (!h) {
		die();
	}

	status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
	if (status < 0) {
		die();
	}

	do{
		status = ipq_read(h, buf, BUFSIZE, 0);
		if (status < 0) {
			die();
		}

		switch (ipq_message_type(buf)) {
		case NLMSG_ERROR:
			fprintf(stderr, "Received error message %d\n",
					ipq_get_msgerr(buf));
			break;

		case IPQM_PACKET: {
			m = ipq_get_packet(buf);

			if(m->hook == NF_IP_LOCAL_IN) {
				encrypt_result = zcc_encrypt(m); 
			} else if (m->hook == NF_IP_LOCAL_OUT) {

				encrypt_result = 1; /* zcc_decrypt(m) */

			} else {
				fprintf(stderr, "Received a packet from a forward queue, we don't know what to \n do with these, perhaps you have a bad configuration rule?\n");
				status = ipq_set_verdict(h, m->packet_id, NF_DROP, 0, NULL);
			}

			if (encrypt_result == 1) {
				status = ipq_set_verdict(h, m->packet_id,
						NF_ACCEPT, 0, NULL);
			} else {
				fprintf(stderr, "Encryption operation failed. Perhaps someone is doing somethign nasty? \n");
				status = ipq_set_verdict(h, m->packet_id,
						 NF_DROP, 0, NULL);
			}
			m = NULL;
			
			if (status < 0) {
				die();
			}
			break;
		}

		default:
			fprintf(stderr, "Unknown message type!\n");
			break;
		}
	} while (1);

	ipq_destroy_handle(h);
}

int main(int argc, char **argv)
{
	/* sa.sa_handler = (void *)bt_sighandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART; 
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL); */

	signal(SIGINT, sigproc);
	signal(SIGQUIT, sigproc);
	process_packets();
	return 0;
}
