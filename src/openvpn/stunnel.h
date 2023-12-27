#ifndef STUNNEL_CLIENT_H
#define STUNNEL_CLIENT_H
const char *init_stunnel(const char *remote_host,
                  const char *remote_port,
                  const char *sni,
                  int ttl);
void start_stunnel();
void stop_stunnel();
const char *stunnel_resolve_remote(const char *host, int *ip_version);
#endif