/* ======================================================================
 * YOU ARE EXPECTED TO MODIFY THIS FILE.
 * ====================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "d2_lookup.h"
#include "d1_udp.h"
#include "d1_udp_mod.h"

enum D2ErrorTypes {
    D2ERROR = 0,
};

D2Client* d2_client_create( const char* server_name, uint16_t server_port )
{
    D1Peer* d1_client = d1_create_client();
    if ( d1_client == NULL ) {
        fprintf(stderr, "Failed to create client!\n");
        return NULL;
    }

    int is_ok = d1_get_peer_info(d1_client, server_name, server_port);
    if ( !is_ok ) {
        fprintf(stderr, "Failed to get peer info!\n");
        return NULL;
    }

    D2Client* d2_client = malloc(sizeof(D2Client));
    if ( d2_client == NULL ) {
        perror("d2 client malloc error");
        return NULL;
    }

    d2_client->peer = d1_client;

    return d2_client;
}

D2Client* d2_client_delete( D2Client* client )
{
    if (client != NULL) {
        d1_delete(client->peer);
        free(client);
    }
    return NULL;
}

int d2_send_request( D2Client* client, uint32_t id )
{
    PacketRequest pr;
    pr.type = htons(TYPE_REQUEST); 
    pr.id = htonl(id);

    int bytes_sent = d1_send_data(client->peer, (char*) &pr, sizeof(PacketRequest));
    if ( bytes_sent < 0 ) return D2ERROR;

    return bytes_sent;
}

int d2_recv_response_size( D2Client* client )
{
    char data[PACKET_PAYLOAD_SIZE];

    int bytes_received = d1_recv_data(client->peer, data, PACKET_PAYLOAD_SIZE);
    if ( bytes_received < (int)sizeof(PacketHeader) ) return ERROR;


    PacketHeader* ph = (PacketHeader*) data;
    uint16_t packet_type = ntohs(ph->type);
    if ( packet_type != TYPE_RESPONSE_SIZE ) return ERROR;

    PacketResponseSize* prs = (PacketResponseSize*) data;
    uint16_t netnodec = ntohs(prs->size);

    return netnodec;
}

int d2_recv_response( D2Client* client, char* buffer, size_t sz )
{
    int bytes_received = d1_recv_data(client->peer, buffer, sz);
    if ( bytes_received < (int)sizeof(PacketHeader) ) return ERROR;
    
    PacketHeader* ph = (PacketHeader*) buffer;
    uint16_t packet_type = ntohs(ph->type);
    if ( !(packet_type == TYPE_RESPONSE || packet_type == TYPE_LAST_RESPONSE) ) return ERROR; 

    return bytes_received;
}

LocalTreeStore* d2_alloc_local_tree( int num_nodes )
{
    LocalTreeStore* tree = malloc(sizeof(LocalTreeStore));
    tree->nodes = malloc(sizeof(NetNode)*num_nodes);
    tree->number_of_nodes = num_nodes;

    return tree;
}

void  d2_free_local_tree( LocalTreeStore* nodes )
{
    free(nodes->nodes);
    free(nodes);
}

int d2_add_to_local_tree( LocalTreeStore* nodes_out, int node_idx, char* buffer, int buflen )
{
    int offset = 0;
    #define GET_NEXT ntohl( *(uint32_t*)(buffer+offset) ); offset += sizeof(uint32_t);

    while (offset < buflen) {
        NetNode* netnode = nodes_out->nodes+node_idx;

        netnode->id           = GET_NEXT;
        netnode->value        = GET_NEXT;
        netnode->num_children = GET_NEXT;
        
        if (netnode->num_children > 5) return D2ERROR; // Stop buffer overflow

        for (uint32_t i=0; i<netnode->num_children; i++) {
            netnode->child_id[i] = GET_NEXT;
        }

        node_idx++;
    }

    return node_idx;
}

void print_node(LocalTreeStore* nodes_out, NetNode* node, int depth)
{
    for (int i=0; i<depth; i++) printf("│   ");

    printf("id %u value %u children %u\n", node->id, node->value, node->num_children);

    for (uint32_t i=0; i<node->num_children; i++) {
        NetNode* child = nodes_out->nodes + node->child_id[i];
        print_node(nodes_out, child, depth+1);
    }
}

void d2_print_tree( LocalTreeStore* nodes_out )
{
    NetNode* root = nodes_out->nodes;
    print_node( nodes_out, root, 0);
}

