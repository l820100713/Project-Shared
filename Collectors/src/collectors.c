#include "collectors.h"

/*
 CITS3002 Project 2015
 Name(s):             Benjamin Sinclair
 Student number(s):   20153423
 Date:
 */


int main(int argc, char *argv[])
{
    int result  = 0;
    char *diraddr;
    char *dirport;
    char *message;
    // Check we have enough arguments
    if(argc < 4) {
        fprintf(stderr, "Usage: %s message address port\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    // Set director port and address
    diraddr = argv[1];
    dirport = argv[2];
    message = argv[3];
    
    // No options right now
    int opt = 0;
    char *optString = OPT_STRING;
    while((opt = getopt(argc, argv, optString)) != -1)
    {
        switch(opt)
        {
        }
    }
    
    // Establish connection with a director
    CONN *conn = establish_connection(diraddr, dirport);
    
    // Register with director
    if(register_with_dir(conn, DEFAULT_SERVICE) != 0) {
        fprintf(stderr, "Error registering with director\n");
        exit(EXIT_FAILURE);
    }
    MSG_HEADER *msg_header = malloc(sizeof(MSG_HEADER));
    msg_header->size = strlen(message) + 1;
    SSL_write(conn->ssl, msg_header, sizeof(MSG_HEADER));
    SSL_write(conn->ssl, message, msg_header->size);
    SSL_read(conn->ssl, msg_header, sizeof(MSG_HEADER));
    char *buf = malloc(msg_header->size);
    SSL_read(conn->ssl, buf, msg_header->size);
    printf("%s\n", buf);
    msg_header->size = 0;
    SSL_write(conn->ssl, msg_header, sizeof(MSG_HEADER));
    free(msg_header);
    
    return result;
}



