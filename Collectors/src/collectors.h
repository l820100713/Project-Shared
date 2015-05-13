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

#define OPT_STRING ""
#define DEFAULT_SERVICE 'a'
#define DEFAULT_PORT "7777"
#define BACKLOG 5
#define CA_CERT "ca.pem"
#define ANA_CERT "certs/cert.pem"
#define ANA_KEY "private/key.pem"


// Connection types
#define ANALYST_CON     0
#define COLLECTOR_CON   1
#define ACCEPT_CON      2
#define ERROR_CON       3


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
} ANALYST_MSG;

typedef struct {
    char                    msg_type;
    char                    service_type;
} COLLECTOR_MSG;

typedef struct {
    char                    msg_type;
    char                    service_type;
} DIRECTOR_MSG;

typedef struct {
    uint32_t                size;
    char                    msg_type;
} MSG_HEADER;

//Structures for this software
typedef struct {
    BIO                     *bio;
    SSL                     *ssl;
    SSL_CTX                 *ctx;
    int                     sd;
} CONN;

// Defined in connections.c
extern  int             init_conn(CONN *conn);
extern  int             load_certs(CONN *conn);
extern  CONN            *establish_connection(char *addr, char *port);
extern  int             register_with_dir(CONN *conn, char service_type);
