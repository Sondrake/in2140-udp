/* ======================================================================
 * YOU ARE EXPECTED TO MODIFY THIS FILE.
 * ====================================================================== */

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "d1_udp.h"

ssize_t receive_packet( struct D1Peer* peer, char* packet_buffer, size_t packet_buffer_size );
int get_packet_header( D1Header* dest, char* packet_buffer, size_t packet_size );
int receive_packet_and_verify_integrity( D1Header* header, struct D1Peer* peer, char* dest_buffer, size_t dest_buffer_size );
int create_packet(char* packet, D1Header* header, char* buffer, size_t sz);
uint16_t gen_checksum( D1Header* header, uint8_t* data_buffer, size_t data_buffer_size, size_t num_data_bytes );
int set_socket_timeout( D1Peer* peer, struct timeval timeout );
int print_error( enum ErrorType err );

D1Peer* d1_create_client()
{
    D1Peer* client = malloc(sizeof(D1Peer));
    if ( client == NULL ) {
        perror("[ERROR]: Client malloc");
        return NULL;
    }

    client->socket = socket(AF_INET, SOCK_DGRAM, 0);
    if ( client->socket < 0 ) {
        perror("[ERROR]: Failed to create socket");
        free(client);
        return NULL;
    }

    memset(&client->addr, 0, sizeof(client->addr));
    client->next_seqno = 0;

    return client;
}

D1Peer* d1_delete( D1Peer* peer )
{
    if ( peer != NULL ) {
        if ( close(peer->socket) < 0 ) perror("[ERROR]: Failed to close socket");
        free(peer);
    }
    return NULL;
}

int d1_get_peer_info( struct D1Peer* peer, const char* peername, uint16_t server_port )
{
    struct addrinfo hints;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = 0;

    struct addrinfo* addr;

    int status = getaddrinfo(peername, NULL, &hints, &addr);
    if ( status < 0 ) {
        fprintf(stderr, "[ERROR]: getaddrinfo - %s\n", gai_strerror(status));
        return 0; // ERROR
    }

    int addressc = 0;
    for ( struct addrinfo* a=addr; a!=NULL; a=a->ai_next ) {
        char ip[INET_ADDRSTRLEN];
        struct sockaddr_in* current_addr = (struct sockaddr_in*) a->ai_addr;

        inet_ntop(current_addr->sin_family, &current_addr->sin_addr, ip, sizeof(ip));
        printf("%d: Resolved IP: %s\n", getpid(), ip);

        addressc++;
    }

    printf("%d: Found %d address%s\n\n",
           getpid(),
           addressc,
           addressc>1 ? "es. Selecting first..." : ""
    );

    struct sockaddr_in* first_addr = (struct sockaddr_in*) addr->ai_addr;

    peer->addr = *first_addr;
    peer->addr.sin_port = htons(server_port);

    freeaddrinfo(addr);
    return 1; // SUCCESS
}

int d1_recv_data( struct D1Peer* peer, char* buffer, size_t sz )
{
    // Set socket to wait on packet forever 
    struct timeval timeout = { 0 /*sec*/, 0 /*usec*/ };
    if ( set_socket_timeout(peer, timeout) < 0 ) return ERROR;

    D1Header header;
    ssize_t payload_size;
    int ackno;

    // Loop until correct packet is received or a fatal error is encountered
    do {
        // Wait for data packet
        payload_size = receive_packet_and_verify_integrity(&header, peer, buffer, sz);
        if ( payload_size == ERROR ) return ERROR;

        printf("%d: Received packet with header: %x %x %x\n", getpid(), header.flags, header.size, header.checksum);

        // Confirm correct flags
        printf("%d: Testing if expected DATA flags (%x) correspond with received flags (%x)\n", getpid(), FLAG_DATA, header.flags);
        uint16_t bitmask = 0b1111111101111111;
        if ( (header.flags & bitmask) != FLAG_DATA ) print_error(WRONG_FLAGS);

        ackno = (uint8_t) header.flags >> 7; // Cut off top byte and shift msb to lsb. Converts from flag bit to an integer value of 0 or 1 

        if ( payload_size == WRONG_CHECKSUM || payload_size == WRONG_SIZE ) {
            d1_send_ack(peer, ackno ^ 1);
        }
    } while ( payload_size < 0 );

    d1_send_ack(peer, ackno);
    printf("\n");

    return payload_size;
}

/* Was not necessary with more args in this implementation. */
int wait_ack( D1Peer* peer )
{
    // Set one second socket timeout
    struct timeval timeout = { 1 /*sec*/, 0 /*usec*/ };
    if ( set_socket_timeout(peer, timeout) < 0 ) return ERROR;

    // Wait for ACK
    D1Header header;
    ssize_t payload_size = receive_packet_and_verify_integrity( &header, peer, NULL, 0 );
    if ( payload_size < 0 ) return payload_size;

    // Confirm correct flags
    uint16_t expected_flags = FLAG_ACK | (uint16_t)peer->next_seqno;
    printf("%d: Testing if expected flags (%x) correspond with received flags (%x)\n", getpid(), expected_flags, header.flags);
    if ( header.flags != expected_flags ) return print_error(WRONG_ACK);

    // Advance SEQNO
    printf("%d: ACK ok! Advancing seqno...\n", getpid());
    peer->next_seqno ^= 1;

    return payload_size;
}

int d1_send_data( D1Peer* peer, char* buffer, size_t sz )
{
    if ( sz > PACKET_PAYLOAD_SIZE ) return ERROR;

    D1Header header;
    header.flags    = FLAG_DATA | ((uint16_t)peer->next_seqno<<7);
    header.size     = sz+PACKET_HEADER_SIZE;
    header.checksum = gen_checksum(&header, (uint8_t*)buffer, sz /*buffer size*/, sz /*data size*/);

    char packet[header.size];
    create_packet(packet, &header, buffer, sz);

    int try = 0;
    int maxtries = 10;
    
    do {
        if (try++ >= maxtries) {
            fprintf(stderr, "[ERROR]: Did not receive satisfactory response after %d tries.\n", maxtries);
            return ERROR;
        } 

        printf("%d: Send packet with header: %x %x %x\n", getpid(), header.flags, header.size, header.checksum);
        sendto(peer->socket, packet, header.size, 0, (struct sockaddr*) &peer->addr, sizeof(peer->addr));

    } while ( wait_ack(peer) < 0 );
    
    return header.size;
}

void d1_send_ack( struct D1Peer* peer, int seqno )
{
    D1Header header;
    header.flags    = FLAG_ACK | (uint16_t)seqno;
    header.size     = PACKET_HEADER_SIZE;
    header.checksum = gen_checksum(&header, NULL, 0, 0);

    char packet[header.size];
    create_packet(packet, &header, NULL, 0);

    printf("%d: ACKing %d\n", getpid(), seqno);
    sendto(peer->socket, packet, header.size, 0, (struct sockaddr*) &peer->addr, sizeof(peer->addr));
}

ssize_t receive_packet( struct D1Peer* peer, char* packet_buffer, size_t packet_buffer_size )
{
    struct sockaddr_in from_addr;
    socklen_t from_addrlen = sizeof(from_addr);

    ssize_t num_bytes_received = recvfrom(peer->socket, packet_buffer, packet_buffer_size, 0, (struct sockaddr*) &from_addr, &from_addrlen);
    if  ( num_bytes_received < 0 ) return print_error(TIMEOUT);
    
    char ip[INET_ADDRSTRLEN];
    inet_ntop(from_addr.sin_family, &from_addr.sin_addr, ip, sizeof(ip));
    printf("%d: Received %ld bytes from %s\n", getpid(), num_bytes_received, ip);

    if ( peer->addr.sin_addr.s_addr != from_addr.sin_addr.s_addr ) return print_error(WRONG_PEER);

    return num_bytes_received;
}

int receive_packet_and_verify_integrity( D1Header* header, struct D1Peer* peer, char* dest_buffer, size_t dest_buffer_size )
{
    char packet_buffer[PACKET_SIZE];
    int err;

    // Wait for packet
    ssize_t num_bytes_received = receive_packet( peer, packet_buffer, PACKET_SIZE );
    if ( num_bytes_received < 0 ) return num_bytes_received;

    // Extract header info
    err = get_packet_header(header, packet_buffer, num_bytes_received);
    if ( err < 0 ) return err;


    int payload_size = num_bytes_received-PACKET_HEADER_SIZE;
    if ( payload_size > 0 && dest_buffer != NULL && (int)dest_buffer_size >= payload_size ) { 
        memcpy(dest_buffer, packet_buffer+PACKET_HEADER_SIZE, payload_size);
    }

    // Compare sizes
    if ( (uint32_t) num_bytes_received != header->size ) return print_error(WRONG_SIZE);

    // Compare checksums
    uint16_t local_checksum = gen_checksum(header, (uint8_t*)dest_buffer, dest_buffer_size, payload_size);
    if ( local_checksum != header->checksum ) return print_error(WRONG_CHECKSUM);

    return payload_size;
}

uint16_t gen_checksum( D1Header* header, uint8_t* data_buffer, size_t data_buffer_size, size_t payload_size )
{
    // Early return error
    if (header == NULL) return 0;

    uint16_t checksum = header->flags 
                      ^ (uint16_t) header->size>>16
                      ^ (uint16_t) header->size;

    // Return checksum early if there's no data available to XOR
    if ( data_buffer == NULL || payload_size == 0 || data_buffer_size < payload_size ) return checksum;

    // XOR pairs of bytes up to last availble pair
    for ( size_t i=0; i<payload_size-1; i+=2 ) {
        checksum ^= (uint16_t) data_buffer[i] << 8 | (uint16_t) data_buffer[i+1];
    }

    // XOR last data byte (msb) padded with 0-byte (lsb) if odd number of total data bytes
    if ( payload_size & 1 ) {
        checksum ^= (uint16_t) data_buffer[payload_size-1] << 8 | 0;
    }

    return checksum;
}

int get_packet_header( D1Header* dest, char* packet_buffer, size_t packet_size )
{
    if (packet_size < sizeof(D1Header)) return print_error(HEADER_ERROR);

    dest->flags    = ntohs( ((uint16_t*)packet_buffer)[0] );
    dest->checksum = ntohs( ((uint16_t*)packet_buffer)[1] );
    dest->size     = ntohl( ((uint32_t*)packet_buffer)[1] );

    return OK;
}

int create_packet(char* packet, D1Header* header, char* buffer, size_t sz)
{
    if (packet == NULL || header == NULL) return ERROR;

    D1Header* ph = (D1Header*)packet;

    ph->flags    = htons(header->flags);
    ph->size     = htonl(header->size);
    ph->checksum = htons(header->checksum);

    if (buffer == NULL || sz == 0) return OK;

    memcpy(packet+PACKET_HEADER_SIZE, buffer, sz);

    return OK;
}

int set_socket_timeout( D1Peer* peer, struct timeval timeout )
{
    if (setsockopt(peer->socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Failed to set timeout sockopt!");
        return ERROR;
    }

    return OK;
}

int print_error( enum ErrorType err )
{
    fprintf(stderr, "[ERROR]: ");

    switch (err) {
        case ERROR:
            fprintf(stderr, "Undefined error occurred!\n");
            break;
        case TIMEOUT:
            fprintf(stderr, "Socket timeout. Did not receive packet from peer!\n");
            break;
        case PACKET_ERROR:
            fprintf(stderr, "Socket error. Did not receive packet from peer!\n");
            break;
        case HEADER_ERROR:
            fprintf(stderr, "Header error. Packet not big enough to include header!\n");
            break;
        case WRONG_PEER:
            fprintf(stderr, "Received packet from wrong peer!\n");
            break;
        case WRONG_SIZE:
            fprintf(stderr, "Header size does not match number of bytes received!\n");
            break;
        case WRONG_CHECKSUM:
            fprintf(stderr, "Header checksum does not match generated checksum!\n");
            break;
        case WRONG_ACK:
            fprintf(stderr, "Received unexpected ACK!\n");
            break;
        case WRONG_FLAGS:
            fprintf(stderr, "Received header flags do not match what was expected!\n");
            break;
        default:
            break;
    }

    return err;
}

