
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
#include <signal.h>
#include <sys/un.h>

// OpenSSL headers

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define OPT_STRING "p:"
#define DEFAULT_PORT "65434"
#define BACKLOG 5
#define CA_CERT "ca.pem"
#define DIR_CERT "certs/cert.pem"
#define DIR_KEY "private/key.pem"

//
// MACROS for protocol
//

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

//
// MACROS for program
//

// Types of info structure
#define ID_LEN          10

#define ANALYST         0
#define COLLECTOR       1


#define FOUND           0
#define NOT_FOUND       1

#define REGISTER_NEW    0
#define CON_CLOSED      1


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
    uint32_t                 size;
    char                     msg_type;
} MSG_HEADER;

// Structures for this software

typedef struct {
    char                    type; // Analyst or collector
    char                    service_type; // Type of service offered/required
    char                    sock_str[ID_LEN]; // Socket string
} INFO;

typedef struct {
    BIO                     *bio;
    SSL                     *ssl;
    SSL_CTX                 *ctx;
    int                     sd;
    char                    sock_str[ID_LEN];
    int                     domain_socket;
} CONN;

typedef struct {
    char                    msg;
    char                    sock_str[ID_LEN]; // Socket string
} MSG;


// Defined in connections.c
extern  int             init_conn(CONN *conn);
extern  int             load_certs(CONN *conn);
extern  CONN            *wait_for_connection(char *port);
extern  int             handle_ipc(CONN *conn);
extern  int             register_client(CONN *conn, INFO *info);
extern  int             serve_client(CONN *conn, INFO *info);
extern  char            check_communication(CONN *conn, int my_id, int their_id);
extern  int             handle_new_connection(CONN *conn, int listen_socket);
extern  int             create_domain_socket(char *sock_str);
extern  int             connect_domain_socket(char *sock_str);



// Defined in lists.c
extern  int             add_entry(INFO **info, INFO *info_entry, int *info_count);
extern  char            *check_match(INFO **info, INFO *collector, int *info_count);
extern  int             remove_entry(INFO **info, char *sock_str, int *info_count);

