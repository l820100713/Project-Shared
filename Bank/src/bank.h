
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

// OpenSSL headers

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 2222
#define BACKLOG 5
#define PORT_STR_LEN 6
#define CA_CERT "ca.pem"
#define DIR_CERT "certs/cert.pem"
#define DIR_KEY "private/key.pem"

// Connection types

#define ANALYST_CON     0
#define BANK_CON        1
#define COLLECTOR_CON   2
#define DIRECTOR_CON    3
#define ACCEPT_CON      4
#define ERROR_CON       5


// Message type

#define NEW_ANALYST     0
#define NEW_COLLECTOR   1
#define DATA            2 
#define SUCCESS_RECEIPT 3
#define ERROR_RECEIPT   4


// Structures as part of protocol

typedef struct {
    char                    msg_size;
    char                    connection_type;
} HAND_SHAKE;

typedef struct {
    char                    msg_type;
    char                    service_type;
    uint16_t                port;
} ANALYST_MSG;

typedef struct {
    char                    msg_type;
    char                    service_type;
    uint16_t                port;
} COLLECTOR_MSG;

typedef struct {
    char                    msg_type;
    char                    service_type;
    uint16_t                port;
} DIRECTOR_MSG;

//Structures for this software

typedef struct {
    BIO                     *bio;
    SSL                     *ssl;
    SSL_CTX                 *ctx;
    int                     sd;
} CONN;

// Defined in connections.c
extern  int             init_conn(CONN *conn);
extern  int             load_trust(CONN *conn);
extern  int             load_certs(CONN *conn);
extern  int             check_certs(CONN *conn);
extern  int             establish_connection(CONN *conn, char *addr, int port);
extern  int             wait_for_connection(CONN *conn, int port);
extern  int             recv_msg(CONN *conn);
extern  int             send_msg(CONN *conn, char *msg, int msg_size);

