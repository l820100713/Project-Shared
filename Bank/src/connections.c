#include "bank.h"

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
    if(!SSL_CTX_use_certificate_file(conn->ctx, DIR_CERT, SSL_FILETYPE_PEM) == 1) {
        perror("certificate\n");
        return -1;
    }
    
    // Load private key
    if(!SSL_CTX_use_PrivateKey_file(conn->ctx, DIR_KEY, SSL_FILETYPE_PEM) == 1) {
        perror("key\n");
        return -1;
    }

    // Load CA certificate
    if(!SSL_CTX_load_verify_locations(conn->ctx, CA_CERT, NULL)) {
        perror("trust\n");
        SSL_CTX_free(conn->ctx);
        return -1;
    }

    return 0;
}

int check_certs(CONN *conn)
{
    if(SSL_get_peer_certificate(conn->ssl) != NULL) {
        if(SSL_get_verify_result(conn->ssl) == X509_V_OK) {
            printf("Verification succeeded\n");
        } else {
            fprintf(stderr, "Getting certificate\n");
            BIO_free_all(conn->bio);
            SSL_CTX_free(conn->ctx);
        }
    } else {
        fprintf(stderr, "No certificate presented\n");
        BIO_free_all(conn->bio);
        SSL_CTX_free(conn->ctx);
        exit(EXIT_FAILURE);
    }
    return 0;
}

int wait_for_connection(CONN *conn, int port)
{
    // Create new SSL structure
    conn->ssl = SSL_new(conn->ctx);
    
    // Set server to verify client cert
    SSL_set_verify(conn->ssl, SSL_VERIFY_PEER, NULL);
    
    // Set up structures for TCP connection
    struct sockaddr_storage their_addr;
    socklen_t addr_size;
    struct addrinfo hints, *res;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me
    
    // Convert port to string
    char str_port[PORT_STR_LEN];
    sprintf(str_port, "%d", port);
    
    getaddrinfo(NULL, str_port, &hints, &res);
    
    // Make a socket
    int listen_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    
    free(res);
    
    int yes=1;
    
    // lose the pesky "Address already in use" error message
    if (setsockopt(listen_socket,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) {
        perror("setsockopt");
        exit(1);
    }
    
    // Bind it to the port
    if(bind(listen_socket, res->ai_addr, res->ai_addrlen) == -1) {
        close(listen_socket);
        perror("bind");
        exit(EXIT_FAILURE);
    }
    
    // Listen to the port
    listen(listen_socket, BACKLOG);
    
    printf("Listening for connection on port %i\n", port);

    addr_size = sizeof their_addr;
    
    // Accept connection
    conn->sd = accept(listen_socket, (struct sockaddr *)&their_addr, &addr_size);
    
    close(listen_socket);
    
    // Set BIO into SSL structure
    conn->bio = BIO_new_socket(conn->sd, BIO_NOCLOSE);
    SSL_set_bio(conn->ssl, conn->bio, conn->bio);
   
    // Perform handshake
    if(SSL_accept(conn->ssl) != 1) {
        perror("SSL handshake");
    }
    
    // Check certificates
    check_certs(conn);
    
    // Print peer ip address
    char *ip_addr_str = malloc(INET_ADDRSTRLEN);
    int their_addrlen = sizeof(their_addr);
    getnameinfo((struct sockaddr *)&their_addr, their_addrlen, ip_addr_str, INET_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);
    printf("IP address is %s\n", ip_addr_str);
    free(ip_addr_str);
    
    return 0;
}

int recv_msg(CONN *conn, ANALYST_INFO **analysts, int *analyst_count, COLLECTOR_INFO **collectors, int *collector_count)
{
    unsigned long ip_addr;
    
    // Receive handshake
    int len = sizeof(HAND_SHAKE);
    HAND_SHAKE *handshake;
    handshake = malloc(len);
    
    if(SSL_read(conn->ssl, handshake, len) < len) {
        fprintf(stderr, "Error receiving handshake\n");
        return -1;
    }
    if(handshake->connection_type == ERROR_CON) {
        fprintf(stderr, "Error received from peer\n");
        return -1;
    }
    
    // Send back handshake confirmation
    HAND_SHAKE *myhandshake;
    myhandshake = malloc(len);
    myhandshake->msg_size = 0;
    myhandshake->connection_type = ACCEPT_CON;
    
    if(SSL_write(conn->ssl, myhandshake, len) < len) {
        fprintf(stderr, "Error sending handshake\n");
        return -1;
    }
    
    free(myhandshake);
    
    // Check what kind of connection we have
    if(handshake->connection_type == ANALYST_CON)
    {
        // Allocate enough space to receive message
        int len = sizeof(ANALYST_MSG) + handshake->msg_size;
                     
        ANALYST_MSG *msg;
        msg = malloc(len);
        
        if(SSL_read(conn->ssl, msg, len) < len) {
            fprintf(stderr, "Error receiving message\n");
            return -1;
        }
        
        if(msg->msg_type == NEW_ANALYST) {
            printf("Received new analyst entry information\n");
            
            // Retreive peer ip address
            struct sockaddr_storage their_addr;
            socklen_t len = sizeof (their_addr);
            getpeername(conn->sd, (struct sockaddr*)&their_addr, &len);
            struct sockaddr_in *ss = (struct sockaddr_in *)&their_addr;
            ip_addr = ntohs(ss->sin_addr.s_addr);
            
            // ANALYST LISTING STUFF - MOVE TO ANOTHER FUNCTION?
            // Search to see if entry already exists for this ip
            bool ip_found = false;
            int index;
            for(index = 0; index < *analyst_count; index ++) {
                int ip = (*analysts)->ip_addr;
                if(ip == ip_addr) {
                    printf("IP address already exists in records, overwriting\n");
                    ip_found = true;
                    break;
                }
                analysts++;
            }
            if(!ip_found) {
                // Create a new analyst entry
                *analyst_count = *analyst_count + 1;
            } else {
                // Free the memory for exisiting entry
                free((*analysts));
            }
            (*analysts) = malloc(sizeof(ANALYST_INFO));
            (*analysts)->service_type = msg->service_type;
            (*analysts)->ip_addr = ip_addr;
            (*analysts)->port = msg->port;
            printf("Service Type : %c\n", msg->service_type);
            printf("Port is : %i\n", msg->port);
            // Put pointer back to beginning of list
            analysts = analysts - index;
            // Send confirmation of success
            char receipt = SUCCESS_RECEIPT;
            if(SSL_write(conn->ssl, &receipt, 1) < 1) {
                fprintf(stderr, "Error sending receipt\n");
                return -1;
            }
        }
        // Free memory
        free(msg);
    }
    if(handshake->connection_type == COLLECTOR_CON) {
        // Do some stuff.
    }
    // Free memory
    free(handshake);
    return 0;
}

