#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 1234

char handshake_msg[] = "SSH-2.0-1.0\r\n";

bool validate_handshake_msg(char *buff) {

}

int main() {
    int listen_socket, client_socket;

    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len;

    if ((listen_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "ERROR: cannot create listening socket.\n");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    if (bind(listen_socket, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "ERROR: cannot bind listening socket.\n");
        exit(1);
    }

    if (listen(listen_socket, 2) < 0) {
        fprintf(stderr, "ERROR: error in listen().\n");
        exit(1);
    }

    if ((client_socket = accept(listen_socket,
                            (struct sockaddr *) &client_addr, &client_addr_len)) < 0) {
        fprintf(stderr, "ERROR: error occurred accepting connection for first player.\n");
        exit(1);
    }
    printf("INFO: Accepted TCP/IP connection from client\n");

    char *msg1 = "Hello ";
    char *msg2 = "world!\n";

    send(client_socket, msg1, 6, 0);
    send(client_socket, msg2, 7, 0);

    close(client_socket);
    return 0;
}
