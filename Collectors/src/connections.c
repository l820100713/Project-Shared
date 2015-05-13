#include "collectors.h"

int init_conn(CONN *conn)
{
    // Initialise OpenSSL
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    
    // Set up the SSL context
    conn->ctx = SSL_CTX_new(SSLv3_method());
    return 0;
}

int load_certs(CONN *conn)
{
    // Load own certificate
    if(!SSL_CTX_use_certificate_file(conn->ctx, ANA_CERT, SSL_FILETYPE_PEM) == 1) {
        perror("certificate");
        return -1;
    }
    // Load private key
    if(!SSL_CTX_use_PrivateKey_file(conn->ctx, ANA_KEY, SSL_FILETYPE_PEM) == 1) {
        perror("key");
        return -1;
    }
    return 0;
}


CONN *establish_connection(char *addr, char *port)
{
    // Blank connection structure
    CONN *conn = malloc(sizeof (CONN));
    // Initialise connection
    init_conn(conn);
    // Load certificates
    load_certs(conn);
    // Create new SSL structure
    conn->ssl = SSL_new(conn->ctx);
    
    struct addrinfo hints, *res;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    getaddrinfo(addr, port, &hints, &res);
    
    conn->sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    
    // Connect to server
    if(connect(conn->sd, res->ai_addr, res->ai_addrlen) != 0) {
        perror("connection");
    }
    
    // Set BIO into SSL structure
    conn->bio = BIO_new_socket(conn->sd, BIO_NOCLOSE);
    SSL_set_bio(conn->ssl, conn->bio, conn->bio);
    
    // Perform handshake
    if(SSL_connect(conn->ssl) != 1) {
        perror("handshake\n");
    }
    
    printf("Connection Established\n");
    return conn;
}

int register_with_dir(CONN *conn, char service_type)
{
    // Set up message with analyst information
    COLLECTOR_MSG *msg;
    
    int msg_size = sizeof(COLLECTOR_MSG);
    
    msg = malloc(msg_size);
    
    msg->msg_type = NEW_COLLECTOR;
    msg->service_type = service_type;
    

    // Set up handshake
    int len = sizeof(HAND_SHAKE);
    HAND_SHAKE *handshake;
    handshake = malloc(len);
    handshake->msg_size = 0;
    handshake->connection_type = COLLECTOR_CON;
    
    // Send handshake
    if(SSL_write(conn->ssl, handshake, len) < len) {
        fprintf(stderr, "Error sending handshake\n");
        return -1;
    }
    
    // Receive handshake confirmation
    HAND_SHAKE *recvhandshake = malloc(len);
    if(SSL_read(conn->ssl, recvhandshake, len) < len) {
        fprintf(stderr, "Error receiving handshake\n");
        return -1;
    }
    
    // Check if handshake was accepted
    if(recvhandshake->connection_type == ACCEPT_CON) {
        printf("Handshake successful\n");
        // Send message
        if(SSL_write(conn->ssl, msg, msg_size) < msg_size) {
            fprintf(stderr, "Error sending message\n");
            return -1;
        }
    } else {
        // Message was declined
        fprintf(stderr, "Handshake error\n");
        return -1;
    }
    // Receive message confirmation
    char *receipt = malloc(1);
    if(SSL_read(conn->ssl, receipt, 1) < 1) {
        fprintf(stderr, "Error receiving receipt confirmation\n");
        return -1;
    }
    if(*receipt != SUCCESS_RECEIPT) {
        // Message error
        fprintf(stderr, "Peer encountered an error receiving message\n");
        return -1;
    }
    return 0;
} 
