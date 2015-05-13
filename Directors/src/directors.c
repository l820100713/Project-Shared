#include "directors.h"

/*
 CITS3002 Project 2015
 Name(s):             Benjamin Sinclair
 Student number(s):   20153423
 Date:
 */


int main(int argc, char *argv[])
{
    int result  = 0;
    char *port = DEFAULT_PORT;
    
    // Only one option right now
    int opt = 0;
    char *optString = OPT_STRING;
    while((opt = getopt(argc, argv, optString)) != -1)
    {
        switch(opt)
        {
            case 'p':
                if(optarg != NULL) {
                    port = optarg;
                } else {
                    fprintf(stderr, "Usage: %s [-p port]\n", argv[0]);
                    exit(EXIT_FAILURE);
                }
                break;
        }
    }
    // Wait for connection from analyst or collector
    CONN *conn = wait_for_connection(port);
    // Set up info structure
    INFO *info = malloc(sizeof(INFO));
    // Wait for message from client
    if(register_client(conn, info) != 0) {
        fprintf(stderr, "Error registering client\n");
    }
    // Serve connected analyst or collector
    serve_client(conn, info);
    
    if(SSL_shutdown(conn->ssl) != 0) {
        perror("shutting down");
    }

    SSL_free(conn->ssl);
    free(conn);
    return result;
}


