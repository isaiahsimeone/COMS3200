#ifndef _RUSHBSRV_H_
#define _RUSHBSRV_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include <poll.h> // for time based retransmission

#include <errno.h>
#include <stdint.h>

#define MAX_CONCURRENT_SESSIONS	2048
#define RUSHB_PACKET_SZ			1472 // not including UDP header
#define MAX_PAYLOAD_SZ 			1464
#define RUSHB_VER				0x2
#define RUSHB_HEADER_SZ			0x8
#define PIPE_READ				0x0
#define PIPE_WRITE				0x1
#define RETRANSMISSION_DELAY	4000 // milliseconds

#define MIN(a,b) (a > b ? b : a)

typedef enum {
	FLG_ACK = 0x40,
	FLG_NAK = 0x20,
	FLG_GET = 0x10,
	FLG_DAT = 0x08,
	FLG_FIN = 0x04,
	FLG_CHK = 0x02,
	FLG_ENC = 0x01
} Flags;

typedef enum {
	RUSHB_OK = 0,
	RUSHB_RETRANSMIT = 1,
	RUSHB_CLOSED = 2,
	RUSHB_DISCARD = 3
} PacketControl;

struct RUSHBPacket {
	uint16_t seq_num;
	uint16_t ack_num;
	uint16_t checksum;
	uint16_t flgs_rsrvd_ver;
	unsigned char payload[MAX_PAYLOAD_SZ];
};

struct Session {
	struct sockaddr_in client_addr;
	pthread_t managing_thread;

	FILE* file_for_tx;

	int write; 		/* Data is put into a session here */
	int read;		/* Thread managing session gets incoming packets here */
	int send_sock;	/* To send data back to client */
	int closed;
	int active;
	int checksum_negotiated;
	int checksum_enabled;

	uint16_t seq_num_of_last_tx;
	uint16_t seq_num_of_last_rx;
};

/*
 * Session tree
 */
struct ST {
	uint16_t src_port; /* Tree node discriminator */
	struct Session* session;
	struct ST* l;
	struct ST* r;
};

/* Prototypes */
void 					ST_insert(struct ST**, uint16_t, struct Session*);
struct ST* 				ST_delete(struct ST**, uint16_t);
struct Session* 		ST_search(struct ST*, uint16_t);
int 					bind_to_ephemeral_port(void);
int 					get_port_from_socket(int);
void					connection_listener(int);
void* 					session_handler(void*);
void 					destroy_session(struct Session*);
struct RUSHBPacket* 	parse_packet(unsigned char*);
int 					generate_response_packet(struct Session*, 
							struct RUSHBPacket*, struct RUSHBPacket**);
uint16_t 				calculate_checksum(struct RUSHBPacket*);
void 					set_packet_RUSHB_ver(struct RUSHBPacket**);

#endif /* _RUSHBSRV_H_ */