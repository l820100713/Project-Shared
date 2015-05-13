#include "bank.h"

int main(int argc, char *argv[])
{
    while(true) {
        // Blank connection structure
        CONN *conn = malloc(sizeof (CONN));
        
        // Initialise connection
        init_conn(conn);
        // Load certificates
        load_certs(conn);
        
        // Wait for connection from analyst or collector
        if(wait_for_connection(conn, PORT) != 0) {
            perror(NULL);
        }
        // Wait for message
        if(recv_msg(conn) != 0) {
            perror(NULL);
        }
        if(SSL_shutdown(conn->ssl) != 0) {
            perror("shutting down");
        }
        if(SSL_shutdown(conn->ssl) < 0) {
            perror("shutdown");
        }
        SSL_free(conn->ssl);
        free(conn);
    }
}


