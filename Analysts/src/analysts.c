#include "analysts.h"

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
    //  TODO Initialise any global variables
    // Check we have enough arguments
    if(argc < 3) {
        fprintf(stderr, "Usage: %s address port\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    // Set director port and address
    diraddr = argv[1];
    dirport = argv[2];
    
    // No options right now
    int opt = 0;
    char *optString = OPT_STRING;
    while((opt = getopt(argc, argv, optString)) != -1)
    {
        switch(opt)
        {
        }
    }
    
    while(true) {
        // Establish connection with a director
        CONN *conn = establish_connection(diraddr, dirport);
        
        // Register with director
        if(register_with_dir(conn) != 0) {
            fprintf(stderr, "Error registering with director\n");
            exit(EXIT_FAILURE);
        }
        MSG_HEADER *msg_header = malloc(sizeof(MSG_HEADER));
        SSL_read(conn->ssl, msg_header, sizeof(MSG_HEADER));
        char *buf = malloc(msg_header->size);
        SSL_read(conn->ssl, buf, msg_header->size);
        char *reverse = reverse_str(buf);
        msg_header->size = strlen(reverse) + 1;
        SSL_write(conn->ssl, msg_header, sizeof(MSG_HEADER));
        SSL_write(conn->ssl, reverse, msg_header->size);
        free(msg_header);
        SSL_free(conn->ssl);
        free(conn);
    }
    return result;
}

char *reverse_str(char *str)
{
    int size = strlen(str);
    char *reverse = malloc(size + 1);
    for(int i = 0; i < size; i ++) {
        reverse[i] = str[size - i - 1];
    }
    reverse[size] = '\0';
    return reverse;
}


