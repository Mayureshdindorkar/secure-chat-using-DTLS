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

char *SERVER_IP;
int SERVER_PORT = 5001;
int CLIENT_PORT = 6001;

union ServerAddrUnion
{
    struct sockaddr_storage ss;
    struct sockaddr_in s4;
    struct sockaddr_in6 s6;
};
struct sockaddr_in msg_exc_client_addr;

void printLine()
{
    printf("\n--------------------------------------------------\n");
}

int cookie_creation_callback(SSL *ssl, unsigned char *cookie, unsigned int *lenth_of_cookie)
{
    *lenth_of_cookie = 6;
    memcpy(cookie, "cookie", 6);
    return 1;
}

int cookie_verification_callback(SSL *ssl, const unsigned char *cookie, unsigned int lenth_of_cookie) { return 1; }

void ssl_info_callback(const SSL *ssl, int where, int ret)
{
    if (where & SSL_CB_HANDSHAKE_START)
    {
        printf(".... DTLS 1.2 Handshake started ....\n\n");
        printf(".... Certificate Verification Started ....\n\n");
    }
    else if (where & SSL_CB_HANDSHAKE_DONE)
    {
        const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
        if (cipher)
        {
            printf(".... Certificate Verification Ended ....\n\n");
            printf("Cipher suite selected by server: %s\n", SSL_CIPHER_get_name(cipher));
        }
        printf("\n.... DTLS 1.2 Handshake ended ....");
        printLine();
    }
}

char *removeLeadingAndTrailingSpaces(char *str)
{
    if (str != NULL)
    {
        char *endPtr;

        // Trim leading spaces
        do
        {
            if (!isspace((unsigned char)*str)) // Exit loop if non-space character is found
                break;
            ++str;
        } while (*str != '\0');

        if (*str == '\0') // All spaces?
            return str;

        // Trim trailing spaces
        endPtr = str + strlen(str) - 1;
        do
        {
            if (!isspace((unsigned char)*endPtr)) // Exit loop if non-space character is found
                break;
            --endPtr;
        } while (endPtr > str);

        // Null terminate the trimmed string
        endPtr[1] = '\0';
    }
    return str;
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

X509_STORE *setup_ca_cert_store(const char *root_ca_cert_file, const char *int_ca_cert_file)
{
    X509_STORE *store = X509_STORE_new();
    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    X509_LOOKUP_load_file(lookup, root_ca_cert_file, X509_FILETYPE_PEM);
    X509_LOOKUP_load_file(lookup, int_ca_cert_file, X509_FILETYPE_PEM);
    return store;
}

// Function to perform certificate expiry date check
int verify_certificate_expiry_date(X509 *cert)
{
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    time_t now = time(NULL);
    struct tm tm_val;
    ASN1_TIME_to_tm(not_after, &tm_val);
    time_t expiry_time = mktime(&tm_val);
    return (now > expiry_time) ? 0 : 1;
}

// This function is called for each certificate in the 'Trust Chain'
int verify_certificate_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    char buf[256];
    X509 *err_cert;
    int err, depth;

    // Extracting the certificate from SSL/DTLS context
    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    // Printing the depth and Subject name of certificate
    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
    printf("Depth:%d, Cert Info: %s\n", depth, buf);
    if (!preverify_ok) {
        printf("Certificate Verification Error: num=%d:%s:%s\n", err, X509_verify_cert_error_string(err), buf);
        exit(1);
    }
    if (preverify_ok) {
        // Verifying the expiry date of certificate
        if (verify_certificate_expiry_date(err_cert)) {
            printf("Certificate having depth %d is NOT expired\n\n", depth);
        } else {
            printf("Error: Certificate is Expired\n");
            exit(1);
        }
    }
    return preverify_ok;
}

SSL_CTX *create_server_context() // bob
{
    // Creating context and filling certs and private key in it
    SSL_CTX *ctx = SSL_CTX_new(DTLSv1_2_server_method());

    // Setting the cipher suits list
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384");
    SSL_CTX_set_info_callback(ctx, ssl_info_callback);

    // Creating trust store for Server
    X509_STORE *store = setup_ca_cert_store("root/root.crt", "int/int.crt");
    SSL_CTX_set_cert_store(ctx, store);

    // SSL/TLS context will not use any session caching. Each new SSL/TLS session will be established without reusing any previously cached session information.
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    // Setting the server private key
    if (!SSL_CTX_use_PrivateKey_file(ctx, "bob/bob_private_key.pem", SSL_FILETYPE_PEM))
    {
        perror("Error occurred while loading bob_private_key.pem");
        exit(EXIT_FAILURE);
    }
    // Setting the server cert
    if (!SSL_CTX_use_certificate_file(ctx, "bob/bob.crt", SSL_FILETYPE_PEM))
    {
        perror("Error occurred while loading bob.crt");
        exit(EXIT_FAILURE);
    }
    // SSL_VERIFY_PEER: the server (or client) will request and verify the certificate of the peer during the SSL/TLS handshake.
    // SSL_VERIFY_CLIENT_ONCE: server should request the client's certificate but only once. Subsequent renegotiations won't require re-authentication.
    // The callback function is a user-defined function that OpenSSL will call during the SSL/TLS handshake to perform additional verification steps or to customize the verification process
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, verify_certificate_callback);
    SSL_CTX_set_verify_depth(ctx, 2);

    // Allows the SSL/TLS library to read as much data as possible from the underlying transport layer (e.g., TCP socket) in a single operation
    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_cookie_generate_cb(ctx, cookie_creation_callback);
    SSL_CTX_set_cookie_verify_cb(ctx, &cookie_verification_callback);
    return ctx;
}

SSL_CTX *create_client_context() // alice
{
    // Creating context and filling certs and private key in it
    SSL_CTX *ctx = SSL_CTX_new(DTLSv1_2_client_method());

    // Setting the cipher suits list of "12 Cipher Suites that support PFS"
    SSL_CTX_set_cipher_list(ctx, "DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256");
    SSL_CTX_set_info_callback(ctx, ssl_info_callback);

    // Creating trust store for Client
    X509_STORE *store = setup_ca_cert_store("root/root.crt", "int/int.crt");
    SSL_CTX_set_cert_store(ctx, store);

    // SSL/TLS context will not use any session caching. Each new SSL/TLS session will be established without reusing any previously cached session information.
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    // Setting the server private key
    if (!SSL_CTX_use_PrivateKey_file(ctx, "alice_2048/alice_private_key.pem", SSL_FILETYPE_PEM))
    {
        perror("Error occurred while loading alice_private_key.pem");
        char buffer[4096];
        printf("%s\n", ERR_error_string(ERR_get_error(), buffer));
        exit(EXIT_FAILURE);
    }

    // Setting the server cert
    if (!SSL_CTX_use_certificate_file(ctx, "alice_2048/alice.crt", SSL_FILETYPE_PEM))
    {
        unsigned long err = ERR_get_error();
        char err_buffer[256];
        ERR_error_string_n(err, err_buffer, sizeof(err_buffer));
        printf("Error occurred while loading alice.crt: %s\n", err_buffer);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_certificate_callback);
    SSL_CTX_set_verify_depth(ctx, 2);
    SSL_CTX_set_read_ahead(ctx, 1);
    return ctx;
}

int exchange_server_messages(int server_socket)
{
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    socklen_t msg_exc_client_addr_size = sizeof(msg_exc_client_addr);
    int n = recvfrom(server_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&msg_exc_client_addr, &msg_exc_client_addr_size);
    printf("Msg recvd from Client: %s\n", buffer);
    if (strcmp(buffer, "chat_hello") != 0)
    {
        printf("\n******** Expected 'chat_hello' message from client ********\n");
        exit(1);
    }

    char *chat_ok_reply = "chat_ok_reply";
    sendto(server_socket, (const char *)chat_ok_reply, strlen(chat_ok_reply), 0, (const struct sockaddr *)&msg_exc_client_addr, sizeof(msg_exc_client_addr));
    printf("Msg sent to Client: %s\n", chat_ok_reply);

    memset(buffer, 0, sizeof(buffer));
    n = recvfrom(server_socket, (char *)buffer, sizeof(buffer), 0, (struct sockaddr *)&msg_exc_client_addr, &msg_exc_client_addr_size);
    if (strcmp(buffer, "chat_START_SSL_NOT_SUPPORTED") != 0)
    {
        printf("Msg recv from Client: %s\n", buffer);
    }
    
    if (strcmp(buffer, "chat_START_SSL_NOT_SUPPORTED") == 0)
    {
        // sendig UNENCRYPTED_CHAT_ACK to trudy
        char *UNENCRYPTED_CHAT_ACK = "UNENCRYPTED_CHAT_ACK";
        sendto(server_socket, (const char *)UNENCRYPTED_CHAT_ACK, strlen(UNENCRYPTED_CHAT_ACK), 0, (const struct sockaddr *)&msg_exc_client_addr, sizeof(msg_exc_client_addr));
        // printf("Msg sent to Client: %s", UNENCRYPTED_CHAT_ACK);
        return 1; // Perform unsecure chatting
    }
    else if (strcmp(buffer, "chat_START_SSL") != 0)
    {
        printf("\n******** Expected 'chat_START_SSL' message from server ********\n");
        exit(1);
    }

    char *chat_START_SSL_ACK = "chat_START_SSL_ACK";
    sendto(server_socket, (const char *)chat_START_SSL_ACK, strlen(chat_START_SSL_ACK), 0, (const struct sockaddr *)&msg_exc_client_addr, sizeof(msg_exc_client_addr));
    printf("Msg sent to Client: %s", chat_START_SSL_ACK);
    return 0; // Perform secure chatting
}

int exchange_client_messages(int client_socket, union ServerAddrUnion server_addr)
{
    // ----------- Message Exchange ------------ //
    char *chat_hello = "chat_hello";
    char buffer[4096];
    sendto(client_socket, (const char *)chat_hello, strlen(chat_hello), 0, (const struct sockaddr *)&server_addr.s4, sizeof(server_addr.s4));
    printf("Msg sent to Server: %s\n", chat_hello);

    memset(buffer, 0, sizeof(buffer));
    socklen_t serv_addr_size = sizeof(server_addr.s4);
    int n = recvfrom(client_socket, (char *)buffer, sizeof(buffer), 0, (struct sockaddr *)&server_addr.s4, &serv_addr_size);
    printf("Msg recv from Server: %s\n", buffer);
    if (strcmp(buffer, "chat_ok_reply") != 0)
    {
        printf("\n******** Expected 'chat_ok_reply' message from server ********\n");
        exit(1);
    }

    char *chat_START_SSL = "chat_START_SSL";
    sendto(client_socket, (const char *)chat_START_SSL, strlen(chat_START_SSL), 0, (const struct sockaddr *)&server_addr.s4, sizeof(server_addr.s4));
    printf("Msg sent to Server: %s\n", chat_START_SSL);

    memset(buffer, 0, sizeof(buffer));
    n = recvfrom(client_socket, (char *)buffer, sizeof(buffer), 0, (struct sockaddr *)&server_addr.s4, &serv_addr_size);
    printf("Msg recv from Server: %s", buffer);
    if (strcmp(buffer, "chat_START_SSL_NOT_SUPPORTED") == 0)
    {
        return 1; // perform unsecure chat
    }
    else if (strcmp(buffer, "chat_START_SSL_ACK") != 0)
    {
        printf("\n******** Expected 'chat_START_SSL_ACK' message from server ********\n");
        exit(1);
    }
    return 0;  // perform secure chat
}

void deallocateMemory(SSL *ssl, int sock)
{
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
}

int create_server_socket()
{
    // Server's info used to bind with server's UDP socket
    int server_socket;
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, SERVER_IP, &(server_addr.sin_addr));
    server_addr.sin_port = htons(SERVER_PORT);

    // Create server socket with some options
    if ((server_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("server socket");
        exit(EXIT_FAILURE);
    }
    const int one = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const void *)&one, (socklen_t)sizeof(one));
    // Bind server socket to server IP and server port
    if (bind(server_socket, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("server socket bind");
        exit(EXIT_FAILURE);
    }
    return server_socket;
}

int create_client_socket()
{
    // ------------------- Socket Connection Code ------------- //
    int client_socket;
    char *clientHostname = getHostnameOfCurrentSystem();
    char *CLIENT_IP = hostname_to_ip(clientHostname);
    printf("Client IP: %s\n", CLIENT_IP);
    printf("Client Port: %d", CLIENT_PORT);

    // Clinet's info used to bind with client's UDP socket
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    inet_pton(AF_INET, CLIENT_IP, &(client_addr.sin_addr));
    client_addr.sin_port = htons(CLIENT_PORT);

    // Create server socket with some options
    if ((client_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("cient socket");
        exit(EXIT_FAILURE);
    }
    // Bind server socket to server IP and server port
    if (bind(client_socket, (const struct sockaddr *)&client_addr, sizeof(client_addr)) < 0)
    {
        perror("client socket bind");
        exit(EXIT_FAILURE);
    }
    return client_socket;
}

void perform_serverside_unsecure_chatting(int bob_socket, struct sockaddr_in trudy_addr) {
    printf("\n\n******** (Unsecured) Chat started ********");
    char buffer[4096];
    printf("\nWaiting for chat msg from Client....\n");
    while(1)
    {
        // Bob (Server) Rceiving msg from Trudy (False Client)
        memset(buffer, 0, sizeof(buffer));
        socklen_t trudy_addr_size = sizeof(trudy_addr);
        int len = recvfrom(bob_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&trudy_addr, &trudy_addr_size);
        printf("Msg recvd from Client: %s\n", buffer);
        if (len > 0)
        {
            if (strcmp(buffer, "chat_close") == 0)
            {
                printf("\n******** Chat closed ********\n");
                return;
            }
        }

        // Bob (Server) Writing msg to Trudy (False Client)
        memset(buffer, 0, sizeof(buffer));
        char reply[1024];
        printf("\nEnter message for Client: ");
        fgets(reply, sizeof(reply), stdin);
        char *trimmed_reply = removeLeadingAndTrailingSpaces(reply);
        len = sendto(bob_socket, (const char *)trimmed_reply, strlen(trimmed_reply), 0, (const struct sockaddr *)&trudy_addr, sizeof(trudy_addr));
        printf("Msg sent to Client: %s\n", trimmed_reply);
        if (len > 0)
        {
            if (strcmp(trimmed_reply, "chat_close") == 0)
            {
                printf("\n******** Chat closed ********\n");
                return;
            }
        }

    }
}

void perform_clientside_unsecure_chatting(int alice_socket, struct sockaddr_in trudy_addr) {
    printf("\n\n******** (Unsecured) Chat started ********");
    char buffer[4096];
    while(1)
    {
        // Alice (Client) Writing msg to Trudy (False server)
        memset(buffer, 0, sizeof(buffer));
        char reply[1024];
        printf("\nEnter message for Server: ");
        fgets(reply, sizeof(reply), stdin);
        char *trimmed_reply = removeLeadingAndTrailingSpaces(reply);
        int len = sendto(alice_socket, (const char *)trimmed_reply, strlen(trimmed_reply), 0, (const struct sockaddr *)&trudy_addr, sizeof(trudy_addr));
        printf("Msg sent to Server: %s\n", trimmed_reply);
        if (len > 0)
        {
            if (strcmp(trimmed_reply, "chat_close") == 0)
            {
                printf("\n******** Chat closed ********\n");
                return;
            }
        }

        // Alice (Client) Rceiving msg from Trudy (False server)
        memset(buffer, 0, sizeof(buffer));
        socklen_t trudy_addr_size = sizeof(trudy_addr);
        len = recvfrom(alice_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&trudy_addr, &trudy_addr_size);
        printf("Msg recvd from Server: %s\n", buffer);
        if (len > 0)
        {
            if (strcmp(buffer, "chat_close") == 0)
            {
                printf("\n******** Chat closed ********\n");
                return;
            }
        }
    }
}

//-----------------------------------------------------------

void runServer()
{
    char *serverHostname = getHostnameOfCurrentSystem();
    printf("Server Info:\n");
    printf("Server Hostname: %s\n", serverHostname);
    SERVER_IP = hostname_to_ip(serverHostname);
    printf("Server IP: %s\n", SERVER_IP);
    printf("Server Port: %d", SERVER_PORT);
    printLine();

    SSL *ssl;
    BIO *bio;
    int server_socket;
    char buffer[4096];
    SSL_CTX *ctx;

    while (1) // Handle Multiple clients
    {
        // Socket Connection Code
        server_socket = create_server_socket();
        printf("Server socket created successfully");
        printLine();

        // Exchanging messages
        printf("Server started listening for new client connection....\n");
        
        // returns 1 if unsecure chatting is to be performed, 0 for secure chatting
        if (exchange_server_messages(server_socket)) {
            perform_serverside_unsecure_chatting(server_socket, msg_exc_client_addr);
            continue;
        }
        printLine();

        // This union will contain client address after successfuly listening to clientHello
        union
        {
            struct sockaddr_storage ss;
            struct sockaddr_in s4;
            struct sockaddr_in6 s6;
        } client_addr;
        memset(&client_addr, 0, sizeof(struct sockaddr_storage));

        // Added Certs & Private key in ctx and then Enabe Cookie
        ctx = create_server_context();

        // Create a UDP BIO
        // BIO_NOCLOSE indicates that the BIO should not close the socket when it is freed
        bio = BIO_new_dgram(server_socket, BIO_NOCLOSE);
        // Setting recv timeout on bio
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        // creates a new SSL/TLS connection (ssl) based on the provided SSL/TLS context
        // context typically contains information about certificates, cipher suites, and other configuration options.
        ssl = SSL_new(ctx);

        // Use same BIO for both reading and writing.
        SSL_set_bio(ssl, bio, bio);
        // enables support for the TLS "Cookie Exchange" extension.
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

        int res = 0;
        while (res < 1) // for waiting till gettig clientHello
        {
            // Listen for incoming DTLS connections
            // Without cookie, vulnerable to Amplification attacks.
            // Solution: validate the source address using 'stateless cookie mechanism'
            res = DTLSv1_listen(ssl, (BIO_ADDR *)&client_addr);
            if (res < 0)
            {
                perror("Error occurred in DTLSv1_listen()");
                exit(EXIT_FAILURE);
            }
        }

        // For Datagram sockets, connect is often used to establish a default destination for sending datagrams.
        if (connect(server_socket, (struct sockaddr *)&client_addr, sizeof(struct sockaddr_in)))
        {
            perror("Error occurred while server connecting to client");
        }

        // Updating the bio with updated socket (this socket now know the destination also)
        BIO_set_fd(SSL_get_rbio(ssl), server_socket, BIO_NOCLOSE);
        BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr.ss);

        int ret;
        do
        {
            ret = SSL_accept(ssl); // At this function call, DTLS handshake occurs and callback function 'ssl_info_callback' gets called.
        } while (ret == 0);
        if (ret < 0)
        {
            perror("Error occurred in SSL_accept");
            printf("%s\n", ERR_error_string(ERR_get_error(), buffer));
            exit(1);
        }
        printf("Server connected to Client using DTLS 1.2");
        printLine();
        BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        // Performing entire chatting (read, write) with currentl connected client
        printf("***** Server has started chatting with Client ******\n");
        while (1)
        {
            // Reading from client
            memset(buffer, 0, sizeof(buffer));
            int len;
            do
            {
                len = SSL_read(ssl, buffer, sizeof(buffer));
            } while (len == -1);
            if (len > 0)
            {
                printf("\nFrom Client: %s", buffer);
                if (strcmp(buffer, "chat_close") == 0)
                {
                    printf("\n******** Chat closed ********\n");
                    break;
                }
            }
            else
            {
                printf("\nReceived some garbage msg from Client: %s", buffer);
            }

            // Writing to Client
            memset(buffer, 0, sizeof(buffer));
            char reply[1024];
            printf("\nEnter message for Client: ");
            fgets(reply, sizeof(reply), stdin);

            char *trimmed_reply = removeLeadingAndTrailingSpaces(reply);
            int l = strlen(trimmed_reply);
            len = SSL_write(ssl, trimmed_reply, l);
            if (len > 0)
            {
                if (strcmp(trimmed_reply, "chat_close") == 0)
                {
                    printf("\n***************** Chat closed *****************\n");
                    break;
                }
            }
            else
            {
                printf("\nError occurrred while sending msg to Client: %s", buffer);
            }
        }
        deallocateMemory(ssl, server_socket);
        printLine();
    }
}

void runClient(char *serverHostName)
{
    // Initializing variables
    SSL *ssl;
    BIO *bio;
    int client_socket;
    SSL_CTX *ctx;
    char buffer[4096];

    printf("Current Client Info:\n");
    client_socket = create_client_socket();
    printLine();
    printf("Client socket created Successfully");
    printLine();

    // Fetching server details from hostname rpovided in cmdline args
    SERVER_IP = hostname_to_ip(serverHostName);
    printf("Client will chat with server:");
    printf("\nServer Hostname: %s\n", serverHostName);
    printf("Server IP (after DNS poisoning): %s\n", SERVER_IP);
    printf("Server Port: %d", SERVER_PORT);
    printLine();

    // Connecting to server
    union ServerAddrUnion server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_storage));
    // Assigning values to above union
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.s4.sin_addr) == 1)
    {
        server_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
        server_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
        server_addr.s4.sin_port = htons(SERVER_PORT);
    }
    // For Datagram sockets, connect is often used to establish a default destination for sending datagrams.
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)))
    {
        perror("client to server connect");
    }

    // returns 1 if unsecure chatting is to be performed, 0 for secure chatting
    if (exchange_client_messages(client_socket, server_addr) == 1){
        perform_clientside_unsecure_chatting(client_socket, server_addr.s4);
        // return 0;
        exit(1);
    }
    printLine();

    // --------------------- Certs, Private key, Verify Private key  -------------//
    ctx = create_client_context();

    // ----------------- SSL Handshake Code ---------------//
    // Create a UDP BIO
    // BIO_NOCLOSE indicates that the BIO should not close the socket when it is freed
    // Wo server ke sath socket connect karke, us socket ka use bio me karra hai
    ssl = SSL_new(ctx);

    bio = BIO_new_dgram(client_socket, BIO_NOCLOSE);

    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &server_addr.ss);
    SSL_set_bio(ssl, bio, bio);
    // SSL Connect
    int retval = SSL_connect(ssl);
    if (retval < 1)
    {
        fprintf(stderr, "Error occurred in SSL connect\n");
        printf("%s\n", ERR_error_string(ERR_get_error(), buffer));
        exit(1);
    }
    printf("Client connected to Server using DTLS");
    printLine();

    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    // Performing entire chatting (read, write) with currentl connected client
    printf("***** Client has started chatting with Server ******\n");
    while (1)
    {
        // Writing msg to Server
        memset(buffer, 0, sizeof(buffer));
        char reply[1024];
        printf("\nEnter message for Server: ");
        fgets(reply, sizeof(reply), stdin);
        char *trimmed_reply = removeLeadingAndTrailingSpaces(reply);

        int l = strlen(trimmed_reply);
        int len = SSL_write(ssl, trimmed_reply, l);
        if (len > 0)
        {
            if (strcmp(trimmed_reply, "chat_close") == 0)
            {
                printf("\n******** Chat closed ********\n");
                break;
            }
        }

        // Reading msg from client
        memset(buffer, 0, sizeof(buffer));
        do
        {
            len = SSL_read(ssl, buffer, sizeof(buffer));
        } while (len == -1);
        if (len > 0)
        {
            printf("\nFrom Server: %s", buffer);
            if (strcmp(buffer, "chat_close") == 0)
            {
                printf("\n******** Chat closed ********\n");
                break;
            }
        }
        else
        {
            printf("\nReceived garbage data from client: %s", buffer);
        }
    }
    deallocateMemory(ssl, client_socket);
    printLine();
}

int main(int argc, char *argv[])
{
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    if (argc == 2)
    {
        runServer();
    }
    else if (argc == 3)
    {
        runClient(argv[2]);
    }
    else
    {
        printf("Wrong command!\n");
        printf("Correct cmd to run Server: ./secure_chat_app -s\n");
        printf("Correct cmd to run Client: ./secure_chat_app -c bob1\n");
        exit(1);
    }
    return 0;
}

// gcc -o secure_chat_app secure_chat_app.c -lssl -lcrypto -Wno-deprecated-declarations
// For Server: ./secure_chat_app -s
// For Client: ./secure_chat_app -c bob1
