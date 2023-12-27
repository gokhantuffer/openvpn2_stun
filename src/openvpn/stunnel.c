#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef TARGET_ANDROID
#include "syshead.h"
#include "socket.h"
#include "ps.h"
#define SSL_HANDSHAKE_TIMEOUT 10
#define SOCKETS_BUFFER_SIZE 4096
#define SOCKET_READ_TIMEOUT 5
#define PORT_SIZE 5

enum stunnel_status {
    NOT_INITIALIZED = -1,
    STOP = 0,
    START = 1
};

int CONTINUE_RUN = NOT_INITIALIZED;
bool STUNNEL_STOPPED = false;
int STUNNEL_SOCKFD;
char LISTEN_PORT_STR[PORT_SIZE+1];
int TTL;
char SNI_HOST[512];
char REMOTE_HOST[512];
char REMOTE_IP[INET6_ADDRSTRLEN+1];
int REMOTE_IP_VERSION;
int REMOTE_PORT;
SSL_CTX *my_default_ssl_context = NULL;

const char* stunnel_resolve_remote(const char* host, int *ip_version) {
    if (CONTINUE_RUN != NOT_INITIALIZED) {
        if (streq(host, REMOTE_HOST)) {
            msg(M_DEBUG, "[STUNNEL] Host is same. Won't resolve dns again: %s, %s", REMOTE_HOST, REMOTE_IP);
            if (ip_version != NULL) {
                *ip_version = REMOTE_IP_VERSION;
            }
            return REMOTE_IP;
        }
    }
    msg(M_DEBUG, "[STUNNEL] Resolve new host: %s", host);
    strcpy(REMOTE_HOST, host);

    struct addrinfo hints, *res, *result;
    int err_code;
    void *ptr;

    memset (&hints, 0, sizeof (hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    err_code = getaddrinfo(host, NULL, &hints, &result);
    if (err_code != 0)
    {
        msg(M_ERR, "[STUNNEL] getaddrinfo failed: %s", strerror(err_code));
    }

    res = result;
    while (res)
    {
        inet_ntop(res->ai_family, res->ai_addr->sa_data, REMOTE_IP, sizeof(REMOTE_IP));

        switch (res->ai_family)
        {
            case AF_INET:
                ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
                break;
            case AF_INET6:
                ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
                break;
        }

        REMOTE_IP_VERSION = res->ai_family;
        inet_ntop(res->ai_family, ptr, REMOTE_IP, sizeof(REMOTE_IP));
        msg(M_DEBUG,"[STUNNEL] IPv%d address: %s (%s)\n", res->ai_family == PF_INET6 ? 6 : 4,
            REMOTE_IP, res->ai_canonname);
        res = res->ai_next;
    }
    freeaddrinfo(result);

    if (ip_version != NULL) {
        *ip_version = REMOTE_IP_VERSION;
    }
    return REMOTE_IP;
}

static bool sock_nonblocking(int fd)
{
    int flag;
    if ((flag = fcntl(fd, F_GETFL, 0)) < 0) return false;
    if (fcntl(fd, F_SETFL, flag | O_NONBLOCK) < 0) return false;
    return true;
}

int create_remote_socket(int ttl, char* remote_host, int remote_port) {
    /* Create socket to connect to remote host */
    int remote_sockfd;
    if ((remote_sockfd = socket(REMOTE_IP_VERSION, SOCK_STREAM, 0)) == -1) {
        msg(M_WARN, "[STUNNEL] Cant get a remote_sockfd! %s", strerror(errno));
        /* perror("socket"); */
        return -1;
    }

    /* Set TTL option for the socket */
    if (ttl > 0 && ttl < 256) {
        msg(M_INFO, "[STUNNEL] Applying ttl: %d", ttl);
        int option_name;
        if (REMOTE_IP_VERSION == AF_INET) {
            option_name = IP_TTL;
        } else {
            /* Hope this will work */
            option_name = IPV6_MULTICAST_HOPS;
        }
        if (setsockopt(remote_sockfd, IPPROTO_IP, option_name, &ttl, sizeof(ttl)) == -1) {
            close(remote_sockfd);
            msg(M_WARN, "[STUNNEL] setsockopt() TTL for remote_sockfd failed! %s", strerror(errno));
            /* perror("setsockopt"); */
            return -1;
        }
    }

    /* Set connection timeout */
    int synRetries = 2; /* Send a total of 3 SYN packets => Timeout ~7s */
    if (setsockopt(remote_sockfd, IPPROTO_TCP, TCP_SYNCNT, &synRetries, sizeof(synRetries)) == -1) {
        close(remote_sockfd);
        msg(M_WARN, "[STUNNEL] setsockopt() timeout(TCP_SYNCNT) for remote_sockfd failed! %s", strerror(errno));
        /* perror("setsockopt"); */
        return -1;
    }

    /* Convert IPv4 and IPv6 addresses from text to binary */
    int result;
    if (REMOTE_IP_VERSION == AF_INET) {
        struct sockaddr_in remote_addr;
        remote_addr.sin_family = REMOTE_IP_VERSION;
        remote_addr.sin_port = htons(remote_port);
        result = inet_pton(AF_INET, remote_host, &remote_addr.sin_addr);
        if (result <= 0) {
            msg(M_WARN, "[STUNNEL] Invalid address/ Address not supported!\n");
            /* perror("setsockopt"); */
            close(remote_sockfd);
            return -1;
        }
        /* Connect to remote host */
        msg(M_INFO, "[STUNNEL] Connecting to remote host: %s...", remote_host);
        result = connect(remote_sockfd, (struct sockaddr*)&remote_addr, sizeof(remote_addr));
    } else {
        struct sockaddr_in6 remote_addr;
        remote_addr.sin6_family = REMOTE_IP_VERSION;
        remote_addr.sin6_port = htons(remote_port);
        result = inet_pton(AF_INET6, remote_host, &remote_addr.sin6_addr);
        if (result <= 0) {
            msg(M_WARN, "[STUNNEL] Invalid address/ Address not supported!\n");
            /* perror("setsockopt"); */
            close(remote_sockfd);
            return -1;
        }
        /* Connect to remote host */
        msg(M_INFO, "[STUNNEL] Connecting to remote host: %s...", remote_host);
        result = connect(remote_sockfd, (struct sockaddr*)&remote_addr, sizeof(remote_addr));
    }

    if (result == -1) {
        /* perror("connect"); */
        msg(M_WARN, "[STUNNEL] Cant connect to remote host! %s", strerror(errno));
        close(remote_sockfd);
        return -1;
    }

    msg(M_INFO, "[STUNNEL] Connected.");
    return remote_sockfd;
}

SSL_CTX* create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    /* Create SSL/TLS context */
    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        /* perror("SSL context creation failed");
         * exit(1);
         */
        msg(M_WARN, "[STUNNEL] SSL context creation failed");
        return NULL;
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    /* Set context options */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
}

SSL* create_ssl_and_configure(SSL_CTX *ctx, int sockfd) {
    /* # Create SSL object */
    SSL *ssl;
    ssl = SSL_new(ctx);
    if (!ssl) {
        /* perror("SSL connection creation failed");
         * exit(1);
         */
        msg(M_WARN, "[STUNNEL] SSL connection creation failed");
        return NULL;
    }
    /* # Configurations
     * 1-) Set SNI
     * SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (void *)my_sni_host);
     */
    long ret = SSL_set_tlsext_host_name(ssl, SNI_HOST);
    if (ret <= 0) {
        /* perror("Setting SNI failed!"); */
        msg(M_WARN, "[STUNNEL] Setting SNI failed!");
        return NULL;
    }
    /* 2-) Set current sockfd to SSL object's fd */
    SSL_set_fd(ssl, sockfd);
    return ssl;
}

SSL* create_secure_socket(int sockfd) {
    /* msg(M_INFO, "[STUNNEL] Creating ssl object..."); */
    /* Create context */
    if (my_default_ssl_context == NULL) {
        /* msg(M_INFO, "[STUNNEL] Creating ssl context first"); */
        my_default_ssl_context = create_context();
        if (my_default_ssl_context == NULL) {
            return NULL;
        }
    }
    /* Set context configuration */
    configure_context(my_default_ssl_context);

    /* Create ssl object and configure it
     * ssl object configurations:
     */
    SSL *ssl = create_ssl_and_configure(my_default_ssl_context, sockfd);
    return ssl;
}

bool ssl_handshake(int sockfd, int timeout, SSL **ssl) {
    int result;
    if (timeout <= 0) {
        result = SSL_connect(*ssl);
        if (result <= 0) {
            int ssl_err = SSL_get_error(*ssl, result);
            msg(M_WARN, "[STUNNEL] SSL Handshake failed with error %d\n", ssl_err);
            return false;
        }
        return true;
    }
    /* Set to non blocking mode */
    if (!sock_nonblocking(sockfd)) {
        msg(M_WARN, "[STUNNEL] Cant set non blocking for SSL sockfd!");
        return false;
    }
    result = SSL_connect(*ssl);
    if (result == 1) {
        msg(M_DEBUG, "[STUNNEL] SSL connection established\n");
        return true;
    }
#if POLL
    /* Create polls */
    struct pollfd poll_fds[1];
    poll_fds[0].fd = sockfd;
    poll_fds[0].events = POLLIN; /* read */
    int poll_timeout = 1000; /* seconds to ms */
    int ready_polls;

    for (int i=0; i < timeout; i++) {
        ready_polls = poll(poll_fds, 1, poll_timeout);
        if (ready_polls == -1) {
            /* perror("poll"); */
            msg(M_WARN, "[STUNNEL] Cant poll! Error: %s", strerror(errno));
            return false;
        } else if (ready_polls == 0) {
            msg(M_WARN, "[STUNNEL] SSL_connect timeout\n");
            return false;
        }
#else
    fd_set read_fdset;
    struct timeval tv; /* Timeout */
    int ready_selects;

    for (int i=0; i < timeout; i++) {
        /* Because select is destructive we need to set some variables in every iteration */
        FD_ZERO(&read_fdset);
        FD_SET(sockfd, &read_fdset);
        tv.tv_sec = timeout;
        tv.tv_usec = 0;

        ready_selects = select(sockfd + 1, &read_fdset, NULL, NULL, &tv);
        if (ready_selects == -1) {
            /* perror("poll"); */
            msg(M_WARN, "[STUNNEL] Cant select! Error: %s", strerror(errno));
            return false;
        } else if (ready_selects == 0) {
            msg(M_WARN, "[STUNNEL] SSL_connect timeout\n");
            return false;
        }
#endif /* POLL */
        result = SSL_connect(*ssl);
        if (result <= 0) {
            int ssl_err = SSL_get_error(*ssl, result);
            if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_NONE) {
                msg(M_DEBUG, "[STUNNEL] Still waiting for ssl handshake...");
            } else {
                msg(M_WARN, "[STUNNEL] SSL_connect failed with error: %d\n", ssl_err);
                return false;
            }
        } else {
            break;
        }
    }
    return true;
}

void free_ssl_context() {
    if (my_default_ssl_context != NULL) {
        SSL_CTX_free(my_default_ssl_context);
        my_default_ssl_context = NULL;
    }
}

bool handle_remote_ssl(SSL** ssl, int* remote_sockfd) {
    /* First create a socket and connect to remote host:port */
    *remote_sockfd = create_remote_socket(TTL, REMOTE_IP, REMOTE_PORT);
    if (*remote_sockfd <= 0) {
        msg(M_WARN, "[STUNNEL] Creating remote socket failed!");
        return false;
    }

    /* Wrap remote socket with SSL */
    *ssl = create_secure_socket(*remote_sockfd);
    if (*ssl == NULL) {
        msg(M_WARN, "[STUNNEL] Looks like something wrong with ssl object");
        close(*remote_sockfd);
        return false;
    }

    /* Perform SSL handshake */
    msg(M_INFO, "[STUNNEL] Doing SSL handshake...");
    if (!ssl_handshake(*remote_sockfd, SSL_HANDSHAKE_TIMEOUT, ssl)) {
        msg(M_WARN, "[STUNNEL] SSL handshake failed");
        close(*remote_sockfd);
        return false;
    }
    msg(M_INFO, "[STUNNEL] SSL handshake successful.");
    return true;
}

void exchange_loop_ssl(int client_sockfd, int remote_sockfd, SSL* ssl) {
    /* Set sockets to non blocking mode */
    if (!sock_nonblocking(client_sockfd)) {
        msg(M_WARN, "[STUNNEL] Cant set non blocking for client_sockfd!");
        return;
    }
    /* Remote socket already set non blocking in while doing SSL handshake */
    if (!sock_nonblocking(remote_sockfd)) {
        msg(M_WARN, "[STUNNEL] Cant set non blocking for remote_sockfd!");
        return;
    }

#if POLL
    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC_RAW, &current_time);
    long time_id = current_time.tv_nsec;

    /* Create polls */
    struct pollfd pollfds[2];
    pollfds[0].fd = client_sockfd;
    pollfds[0].events = POLLIN;
    pollfds[1].fd = remote_sockfd;
    pollfds[1].events = POLLIN | POLLOUT;
    int poll_timeout = SOCKET_READ_TIMEOUT*1000; /* seconds to ms */
    /* For receiving and sending data declare variables */
    char buffer_read[SOCKETS_BUFFER_SIZE];
    char buffer_write[SOCKETS_BUFFER_SIZE];
    int ready_polls, bytes_read, bytes_send;
    ssize_t recv_len = 0;

    msg(M_INFO, "[STUNNEL] In exchange loop");
    while (CONTINUE_RUN) {
        ready_polls = poll(pollfds, 2, poll_timeout); /* 2 = how many sockets */
        if (ready_polls == -1) {
            break;
        } else if (ready_polls == 0) { /* Nothing from sockets */
            /* Nothing to do */
            /* msg(M_DEBUG, "[STUNNEL] Ready poll is 0"); */
            continue;
        } else {
            if ((pollfds[0].revents & POLLIN)) {
                /* Receive data from the client */
                if ((recv_len = recv(client_sockfd, buffer_read, sizeof(buffer_read), 0)) <= 0) {
                    /* perror("recv"); */
                    msg(M_WARN, "[STUNNEL] Cant recv from client! %s", strerror(errno));
                    break;
                }
                pollfds[0].events &= ~POLLIN;
                pollfds[1].events |= POLLOUT;
            }

            if ((pollfds[1].revents & POLLOUT)) {
                /* Send the received data to the secure socket */
                bytes_send = SSL_write(ssl, buffer_read, (int)recv_len);
                if (bytes_send <= 0) {
                    /* perror("Error in sending data to secure socket"); */
                    int err = SSL_get_error(ssl, bytes_send);
                    msg(M_WARN, "[STUNNEL] Error in sending data to secure socket. Errno: %d", err);
                    break;
                }
                pollfds[1].events &= ~POLLOUT;
                pollfds[0].events |= POLLIN;
            }

            if (pollfds[1].revents & POLLIN) {
                bytes_read = SSL_read(ssl, buffer_write, sizeof(buffer_write));
                if (bytes_read < 0) {
                    /* perror("Error in receiving data from secure socket"); */
                    int err = SSL_get_error(ssl, bytes_read);
                    /* https://stackoverflow.com/questions/31171396/openssl-non-blocking-socket-ssl-read-unpredictable */
                    /* if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_NONE) { */
                    if (err == SSL_ERROR_WANT_READ) {
                        /* Data not available */
                        continue;
                    }
                    msg(M_WARN, "[STUNNEL] Error in receiving data from secure socket. Errno: %d", err);
                    break;
                } else if (bytes_read == 0) {
                    /* printf("Secure socket has no more data to process.\n"); */
                    msg(M_WARN, "[STUNNEL] [-%ld-] bytes read is 0", time_id);
                    continue;
                } else {
                    /* Send received data to the client */
                    if (send(client_sockfd, buffer_write, (size_t)bytes_read, 0) <= 0) {
                        msg(M_WARN, "[STUNNEL] Cant send to client! %s", strerror(errno));
                        /* perror("send"); */
                        break;
                    }
                }
            }
        }
    }
    msg(M_DEBUG, "[STUNNEL] Exiting from ssl poll loop");
#else /* POLL */
    /* For select api declare variables and initialize some of them */
    fd_set read_fds;
    int max_fd = (client_sockfd > remote_sockfd) ? client_sockfd : remote_sockfd;
    struct timeval tv; /* Timeout */

    /* For receiving and sending data declare variables */
    char buffer[SOCKETS_BUFFER_SIZE];
    int ready_selects, bytes_read, bytes_send;
    ssize_t recv_len;

    msg(M_DEBUG, "In exchange loop");
    while (CONTINUE_RUN) {
        FD_ZERO(&read_fds);
        FD_SET(client_sockfd, &read_fds);
        FD_SET(remote_sockfd, &read_fds);
        /* Because select is destructive we need to set timeout in every iteration */
        tv.tv_sec = SOCKET_READ_TIMEOUT;
        tv.tv_usec = 0;
        /* Wait for activity on either client or remote socket */
        if ((ready_selects = select(max_fd + 1, &read_fds, NULL, NULL, &tv)) == -1) {
            /* perror("select"); */
            msg(M_WARN, "Cant select! %s", strerror(errno));
            break;
        }

        if (ready_selects == 0)
            continue;

        /* Data available on the client socket */
        if (FD_ISSET(client_sockfd, &read_fds)) {
            /* Receive data from the client */
            if ((recv_len = recv(client_sockfd, buffer, sizeof(buffer), 0)) <= 0) {
                /* perror("recv"); */
                msg(M_WARN, "Cant recv from client! %s", strerror(errno));
                break;
            }

            /* Send the received data to the secure socket */
            bytes_send = SSL_write(ssl, buffer, (int)recv_len);
            if (bytes_send <= 0) {
                /* perror("Error in sending data to secure socket"); */
                int err = SSL_get_error(ssl, bytes_send);
                msg(M_WARN, "Error in sending data to secure socket. Errno: %d", err);
                break;
            }
        }

        /* Data available on the remote socket */
        if (FD_ISSET(remote_sockfd, &read_fds)) {
            bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
            if (bytes_read < 0) {
                /* perror("Error in receiving data from secure socket"); */
                int err = SSL_get_error(ssl, bytes_read);
                /* https://stackoverflow.com/questions/31171396/openssl-non-blocking-socket-ssl-read-unpredictable */
                /* if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_NONE) { */
                if (err == SSL_ERROR_WANT_READ) {
                    /* Data not available */
                    continue;
                }
                msg(M_WARN, "Error in receiving data from secure socket. Errno %d", err);
                break;
            } else if (bytes_read == 0) {
                /* printf("Secure socket has no more data to process.\n"); */
                continue;
            } else {
                /* Send received data to the client */
                if (send(client_sockfd, buffer, (size_t)bytes_read, 0) <= 0) {
                    msg(M_WARN, "Cant send to client! %s", strerror(errno));
                    /* perror("send"); */
                    break;
                }
            }
        }
    }
    msg(M_DEBUG, "Exiting from selects ssl loop.");
#endif /* POLL */
}

void handle_stunnel_accept(int client_sockfd) {
    /* Handle remote and if something wrong free allocations and return */
    SSL* ssl = NULL;
    int remote_sockfd;
    if (!handle_remote_ssl(&ssl, &remote_sockfd)) {
        close(client_sockfd);
        if (ssl != NULL) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            free_ssl_context();
        }
        return;
    }

    if (ssl == NULL) {
        msg(M_WARN, "[STUNNEL] ssl object is still null!");
        close(client_sockfd);
        close(remote_sockfd);
        return;
    }

    /* Now do data exchange between client and remote */
    exchange_loop_ssl(client_sockfd, remote_sockfd, ssl);
    /* Close client and remote connections */
    close(client_sockfd);
    close(remote_sockfd);
    /* Free ssl */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    free_ssl_context();
}

int create_listening_socket() {
    struct sockaddr_in server_addr;
    /* Create server socket */
    if ((STUNNEL_SOCKFD = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        msg(M_WARN, "[STUNNEL] Cant create STUNNEL_SOCKFD! %s", strerror(errno));
        return -1;
    }

    /* Allow socket descriptor to be reuseable */
    int ret_code, on = 1;
    ret_code = setsockopt(
            STUNNEL_SOCKFD,
            SOL_SOCKET, SO_REUSEADDR,
            (char *)&on, sizeof(on)
    );
    if (ret_code < 0) {
        msg(M_WARN, "[STUNNEL] setsockopt() reuse address for STUNNEL_SOCKFD failed! %s",
            strerror(errno));
        close(STUNNEL_SOCKFD);
        return -1;
    }

    /* Set server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    /* server_addr.sin_addr.s_addr = inet_addr("0.0.0.0"); */
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server_addr.sin_port = htons(0);

    /* Bind server socket to the specified address */
    if (bind(STUNNEL_SOCKFD, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        msg(M_WARN, "[STUNNEL] Binding for STUNNEL_SOCKFD failed! %s", strerror(errno));
        close(STUNNEL_SOCKFD);
        return -1;
    }

    /* Get the assigned port */
    socklen_t len = sizeof(server_addr);
    if (getsockname(STUNNEL_SOCKFD, (struct sockaddr*)&server_addr, &len) == -1) {
        msg(M_WARN, "[STUNNEL] Getting the port number assigned to STUNNEL_SOCKFD failed! %s",
            strerror(errno));
        close(STUNNEL_SOCKFD);
        return -1;
    }
    int listen_port = ntohs(server_addr.sin_port);

    /* Start listening for client connections */
    if (listen(STUNNEL_SOCKFD, 5) == -1) {
        msg(M_WARN, "[STUNNEL] Listening for STUNNEL_SOCKFD failed! %s", strerror(errno));
        close(STUNNEL_SOCKFD);
        return -1;
    }
    return listen_port;
}

void get_a_free_local_port() {
    int listen_port = create_listening_socket();
    if (listen_port != -1) {
        snprintf(LISTEN_PORT_STR, PORT_SIZE+1, "%d", listen_port);
    } else {
        /* This(M_ERR) will stop the code */
        msg(M_ERR, "[STUNNEL] Cant create listening server!");
    }
}

void *stunnel_server(void *thread_arg) {
    msg(M_INFO, "[STUNNEL] Running listening stunnel server...");
    CONTINUE_RUN = START;
    STUNNEL_STOPPED = false;

    int client_sockfd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    /* Accept incoming client connection */
    msg(M_INFO, "[STUNNEL] Accepting...");
    client_sockfd = accept(STUNNEL_SOCKFD, (struct sockaddr*)&client_addr, &client_len);
    if (client_sockfd == -1) {
        msg(M_WARN, "[STUNNEL] Accepting for STUNNEL_SOCKFD failed! %s", strerror(errno));
    } else {
        msg(M_INFO, "[STUNNEL] Accepted connection.");
        /* msg(M_INFO, "[STUNNEL] Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port)); */
        handle_stunnel_accept(client_sockfd);
    }

    STUNNEL_STOPPED = true;
    close(STUNNEL_SOCKFD);
    STUNNEL_SOCKFD = -1;
    msg(M_INFO, "[STUNNEL] Server closed.");
    return NULL;
}

const char* init_stunnel(const char* remote_host,
                         const char* remote_port,
                         const char *sni,
                         int ttl) {
    stunnel_resolve_remote(remote_host, NULL);
    REMOTE_PORT = atoi(remote_port);
    strcpy(SNI_HOST, sni);
    TTL = ttl;
    get_a_free_local_port();
    return LISTEN_PORT_STR;
}

void start_stunnel() {
    /* Start stunnel in another thread */
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, stunnel_server, NULL);
    pthread_detach(thread_id);
}

void stop_stunnel() {
    if (CONTINUE_RUN == START) {
        if (!STUNNEL_STOPPED) {
            msg(M_INFO, "[STUNNEL] Stopping server...");
        }
        CONTINUE_RUN = STOP;
    }
}
#endif /* TARGET_ANDROID */