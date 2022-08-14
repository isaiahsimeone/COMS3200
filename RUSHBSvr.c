#include "RUSHBSvr.h"

/*
 * Each client is serviced by a single thread.
 * UDP datagrams arriving at the incoming end of the main socket
 * are forwarded to the appropriate managing thread based upon
 * 1) The source port of the incoming datagram (IP doesn't matter)
 * since this will only be run on localhost
 */

/* Globals */
struct ST* session_tree;
pthread_mutex_t session_tree_lck;

/*
 * Usage: ./RUSHBSvr
 */
int main(int argc, char** argv) {
	/* Bind and listen on ephemeral port */
	int sock = bind_to_ephemeral_port();

	printf("%d\n", get_port_from_socket(sock));
	fflush(stdout);

	pthread_mutex_init(&session_tree_lck, NULL);	

	connection_listener(sock);

	return 0;
}

/*
 * If this is the first message from this specific client, 
 * create a new entry in the session tree and spawn a thread
 * If this is an ongoing transaction, forward the datagram
 * to the managing thread 
 */
void connection_listener(int socket) {
	session_tree = NULL;
	
	pthread_mutex_init(&session_tree_lck, NULL);

	struct Session* session;
	struct sockaddr_in client_addr;
	unsigned int len = sizeof(client_addr);

	char buf[RUSHB_PACKET_SZ];
	memset(buf, 0, RUSHB_PACKET_SZ);
	pthread_t tid;
	int thread_fd[2];

	/* recv loop */
	for (;;) {
		recvfrom(socket, (char*)buf, RUSHB_PACKET_SZ, MSG_WAITALL,
			(struct sockaddr*)&client_addr, &len);

		pthread_mutex_lock(&session_tree_lck);
		/* Check if this session already exists based on source port */
		if (!ST_search(session_tree, ntohs(client_addr.sin_port))) {
			/* Session was not found - create a new one */

			session = malloc(sizeof(struct Session));
			memset(session, 0, sizeof(struct Session));

			session->client_addr = client_addr;
			session->send_sock = socket;

			if (pipe(thread_fd) < 0) {
				perror("pipe() thread_fd\n");
				continue; // just discard this message and hope for the best
			}

			session->read = thread_fd[PIPE_READ];
			session->write = thread_fd[PIPE_WRITE];

			session->file_for_tx = NULL;
			session->seq_num_of_last_tx = 0;
			session->seq_num_of_last_rx = 0;
			session->checksum_enabled = 0;
			session->checksum_negotiated = 0;
			session->closed = 0;
			session->active = 0;

			pthread_create(&tid, 0, session_handler, (void*)session);
			/* Insert the session into the session tree */
			ST_insert(&session_tree, ntohs(client_addr.sin_port), session);
		}

		/* Identify which session is responsible and 'pipe' the data to it */
		session = ST_search(session_tree, ntohs(client_addr.sin_port));
		pthread_mutex_unlock(&session_tree_lck);

		if (session == NULL)
			perror("Session not found, and not inserted???");

		/* Write incoming datagram to managing thread */
		write(session->write, buf, RUSHB_PACKET_SZ);

		memset(buf, 0, RUSHB_PACKET_SZ);
	}
}

/*
 * Service a single client connection. Rx incoming packets,
 * tx responses to that client only
 */
void* session_handler(void* session_args) {
	struct Session* session = (struct Session*)session_args;

	session->managing_thread = pthread_self();
	
	unsigned char buf[RUSHB_PACKET_SZ];
	memset(buf, 0, RUSHB_PACKET_SZ);

	struct RUSHBPacket* incoming_packet;
	struct RUSHBPacket* outgoing_packet;
	struct RUSHBPacket last_outgoing_packet;

	int ret_stat = RUSHB_OK;

	struct pollfd *pfds = malloc(sizeof(struct pollfd));
	memset(pfds, 0, sizeof(struct pollfd));
	pfds[0].fd = session->read; 
	pfds[0].events |= POLLIN; 

	int timeout_retransmission = 0;

	for (;;) {
		/* Session is active, but nothing received in 4 seconds. retransmit */
		if (session->active && poll(pfds, 1, RETRANSMISSION_DELAY) == 0)
			timeout_retransmission = 1;
		else {
			read(session->read, buf, RUSHB_PACKET_SZ);
			
			incoming_packet = parse_packet(buf);

			ret_stat = generate_response_packet(session, incoming_packet,
				&outgoing_packet);

			free(incoming_packet);

			/* Maintain last outgoing packet in case of retransmission */
			if (ret_stat == RUSHB_RETRANSMIT)
				outgoing_packet = &last_outgoing_packet;
			else if (ret_stat == RUSHB_OK)
				last_outgoing_packet = *outgoing_packet;

			timeout_retransmission = 0;
		}

		/* Send outgoing packet */
		sendto(session->send_sock, outgoing_packet, RUSHB_PACKET_SZ, MSG_CONFIRM,
			(struct sockaddr*)&session->client_addr, sizeof(session->client_addr));
		session->active = 1;

		/* Last packet ACK'd. Won't be retransmitted */
		if (ret_stat == RUSHB_OK && !timeout_retransmission)
			free(outgoing_packet);

		/* Session closed */
		if (ret_stat == RUSHB_CLOSED) 
			destroy_session(session);
	}
	/* Not reached */
	return NULL;
}

/*
 * Given an incoming RUSHB packet, generate the appropriate response packet
 */
int generate_response_packet(struct Session* session, 
		struct RUSHBPacket* incoming, struct RUSHBPacket** outgoing) {
	uint8_t iflags = incoming->flgs_rsrvd_ver >> 0x9; // isolate top 7 bits
	uint8_t oflags = 0;
	int file_bytes_read;

	struct RUSHBPacket* packet = malloc(sizeof(struct RUSHBPacket));
	memset(packet, 0, sizeof(struct RUSHBPacket));

	int ret_stat = RUSHB_OK;
	uint16_t expected_rx_seq_num = session->seq_num_of_last_rx + 1;
	
	/* Set packet version */
	set_packet_RUSHB_ver(&packet);

	/* Checksum flag not set in negotiated checksum communication */
	if (session->checksum_negotiated && !(iflags & FLG_CHK))
		return RUSHB_RETRANSMIT;

	/* Invalid checksum. Discard packet */
	if (iflags & FLG_CHK && incoming->checksum != calculate_checksum(incoming))
		return RUSHB_DISCARD;

	/* Bad client header. Not actionable */
	if (!(iflags & FLG_ACK) && !(iflags & FLG_GET) && !(iflags & FLG_NAK))
		return RUSHB_RETRANSMIT;

	/* Incoming sequence number doesn't match expected */
	if (incoming->seq_num != expected_rx_seq_num)
		return RUSHB_RETRANSMIT;

	/* Client has ACK number we didn't expect */
	if (iflags & FLG_ACK && incoming->ack_num != session->seq_num_of_last_tx)
		return RUSHB_RETRANSMIT;

	if (session->closed) {
		/* Last TX was FIN, but didn't get FIN/ACK back */
		if (!(iflags & FLG_FIN && iflags & FLG_ACK))
			return RUSHB_RETRANSMIT;
		else {
			/* Connection closed */
			oflags |= FLG_FIN;
			oflags |= FLG_ACK;
			packet->ack_num = incoming->seq_num;
			ret_stat = RUSHB_CLOSED;
		}
	}

	/* Incoming packet did not ACK most recently transmitted */
	if ((iflags & FLG_DAT && iflags & FLG_ACK) 
			&& incoming->ack_num != session->seq_num_of_last_tx)
		return RUSHB_RETRANSMIT;

	/* Client is requesting file */
	if (iflags & FLG_GET) {
		/* Client attempted GET during a transmission */
		if (incoming->seq_num != 1 && session->file_for_tx != NULL)
			return RUSHB_RETRANSMIT;

		/* Client wishes to use checksum */
		if (iflags & FLG_CHK)
			session->checksum_enabled = 1;

		if (session->file_for_tx != NULL)
			printf("Client requested file, but one is already open for tx\n");
		else {
			//open the file
			session->file_for_tx = fopen(incoming->payload, "rb");
			/* ENOENT or EACCES */
			if (!session->file_for_tx)
				return RUSHB_CLOSED;
		}
		/* Hack to ensure iflags & FLG_DAT == 1*/
		iflags |= FLG_DAT;
	}

	/* Checksum negotiation complete */
	if (session->checksum_enabled) {
		if (!session->checksum_negotiated)
			session->checksum_negotiated = 1;
		oflags |= FLG_CHK;
	}

	/* Received good sequence number */
	session->seq_num_of_last_rx = incoming->seq_num;

	/* Incoming packet has NAK flag set - retransmit */
	if (iflags & FLG_NAK) 
		return RUSHB_RETRANSMIT;

	/* Data packet: Send more of the file */
	if (iflags & FLG_DAT) {
		if (feof(session->file_for_tx)) {
			oflags |= FLG_FIN;
			session->closed = 1;
			fclose(session->file_for_tx);
			session->file_for_tx = NULL;
		} else {
			/* Copy next block of file into outbound payload */
			file_bytes_read = fread(packet->payload, 1, 
				MAX_PAYLOAD_SZ, session->file_for_tx);

			/* Pad if necessary */
			memset(packet->payload + file_bytes_read, 0, 
					RUSHB_PACKET_SZ - file_bytes_read);

			oflags |= FLG_DAT;
		}
	}

	/* Load checksum into packet */
	if (session->checksum_enabled)
		packet->checksum = calculate_checksum(packet);

	/* Set version & reserved/version bits */
	packet->flgs_rsrvd_ver |= (oflags << 0x9);
	packet->seq_num = session->seq_num_of_last_tx + 1;

	session->seq_num_of_last_tx++;

	/* To network byte order */
	packet->flgs_rsrvd_ver = ntohs(packet->flgs_rsrvd_ver);
	packet->ack_num = ntohs(packet->ack_num);
	packet->seq_num = ntohs(packet->seq_num);
	packet->checksum = ntohs(packet->checksum);

	*outgoing = packet;

	return ret_stat;
}

/*
 * Carry around add from spec sheet
 */
int carry_arnd_add(int a, int b) {
	int c = a + b;
	return (c & 0xffff) + (c >> 16);
}

/*
 * Calculate checksum according to spec sheet
 */
uint16_t calculate_checksum(struct RUSHBPacket* packet) {
	int checksum = 0;

	for (int i = 0; i < MAX_PAYLOAD_SZ; i += 2)
		checksum = carry_arnd_add(checksum, (packet->payload[i] << 0)
					+ (packet->payload[i + 1] << 0x8));
	
	return ~checksum & 0xffff;
}

/*
 * Sets the lowest 3 bits in the specified RUSHB packet
 */
void set_packet_RUSHB_ver(struct RUSHBPacket** packet) {
	(*packet)->flgs_rsrvd_ver = RUSHB_VER;
}

/*
 * Pack raw packet into RUSHBPacket struct
 */
struct RUSHBPacket* parse_packet(unsigned char* buf) {
	struct RUSHBPacket* packet = malloc(sizeof(struct RUSHBPacket));
	memset(packet, 0, sizeof(struct RUSHBPacket));
	memcpy(packet, buf, RUSHB_PACKET_SZ);

	/* Network to host byte order */
	packet->seq_num = ntohs(packet->seq_num);
	packet->ack_num = ntohs(packet->ack_num);
	packet->checksum = ntohs(packet->checksum);
	packet->flgs_rsrvd_ver = ntohs(packet->flgs_rsrvd_ver);

	return packet;
}

/*
 * Destroy the specified session. Deallocate all resources
 * that it was using then remove from session tree
 */
void destroy_session(struct Session* session) {
	struct sockaddr_in client_addr = session->client_addr;

	/* delete from session tree */
	pthread_mutex_lock(&session_tree_lck);
	ST_delete(&session_tree, ntohs(client_addr.sin_port));
	pthread_mutex_unlock(&session_tree_lck);

	/* close fd's */
	close(session->read);
	close(session->write);
	if (session->file_for_tx)
		fclose(session->file_for_tx);

	/* Free session */
	free(session);

	pthread_exit(0);
}

/**
 * Creates a new socket and assigns an address (port) to the socket.
 * The assigned address will be an ephemeral port available on localhost
 *
 * Returns:   A file descriptor of the newly created socket
 *            which is bound to a free port on the local machine.
 */
int bind_to_ephemeral_port() {
	struct sockaddr_in sai;

	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	sai.sin_family = AF_INET;
	sai.sin_addr.s_addr = inet_addr("127.0.0.1");
	sai.sin_port = 0;

	bind(sock, (struct sockaddr*)&sai, sizeof(sai));

	return sock;
}

/**
 * Determines the port that is bound with the specified socket.
 *
 *  socket:   A file descriptor of a socket
 *    
 * Returns:   The port bound to the specified socket, or -1 in error
 */
int get_port_from_socket(int socket) {
	struct sockaddr_in sai;
	socklen_t len = sizeof(sai);
	int port = -1;

	if (getsockname(socket, (struct sockaddr *)&sai, &len) == 0)
		port = ntohs(sai.sin_port);
	
	return port;
}
