/* ======================================================================
 * YOU CAN MODIFY THIS FILE.
 * ====================================================================== */

#ifndef D1_UDP_MOD_H
#define D1_UDP_MOD_H

#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PACKET_SIZE 1024
#define PACKET_HEADER_SIZE sizeof(D1Header)
#define PACKET_PAYLOAD_SIZE ( PACKET_SIZE - PACKET_HEADER_SIZE )

/* This structure keeps all information about this client's association
 * with the server in one place.
 * It is expected that d1_create_client() allocates such a D1Peer object
 * dynamically, and that d1_delete() frees it.
 */
struct D1Peer
{
    int32_t            socket;      /* the peer's UDP socket */
    struct sockaddr_in addr;        /* addr of my peer, initialized to zero */
    int                next_seqno;  /* either 0 or 1, initialized to zero */
};

typedef struct D1Peer D1Peer;

enum ErrorType {
    OK             =  0,
    ERROR          = -1,
    TIMEOUT        = -2,
    HEADER_ERROR   = -3,
    PACKET_ERROR   = -4,
    WRONG_CHECKSUM = -5,
    WRONG_SIZE     = -6,
    WRONG_ACK      = -7,
    WRONG_FLAGS    = -8,
    WRONG_PEER     = -9,
};

#endif /* D1_UDP_MOD_H */

