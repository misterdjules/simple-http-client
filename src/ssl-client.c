#include <stdio.h>

#include <openssl/ssl.h>

#define MAX_TCP_PORT_STR_LENGTH                 5
#define DEFAULT_HTTPS_PORT                      443
#define ADDITIONAL_TRUSTED_CA_BUNDLE_PATH       "../certs/go_daddy_ca_bundle.pem"
#define HTTP_BUFFER_SIZE                        1024

void init_openssl(void)
{
  SSL_load_error_strings();
  SSL_library_init();
  seed_prng(128);
}

typedef struct cmd_line_options {
  char* server_host_name;
} cmd_line_options_t;

void print_usage(void)
{
  fprintf(stderr, "Usage:\n"\
          "ssl-client host\n");
}

int parse_cmd_line_options(int argc, char* argv[], cmd_line_options_t* res)
{
  if (argc != 2)
  {
    return 0;
  }

  res->server_host_name = strdup(argv[1]);

  return 1;
}

int ssl_verify_cert_callback(int ok, X509_STORE_CTX* store)
{
  char data[256];

  if (!ok)
  {
    X509* cert  = X509_STORE_CTX_get_current_cert(store);
    int depth   = X509_STORE_CTX_get_error_depth(store);
    int err     = X509_STORE_CTX_get_error(store);

    fprintf(stderr, "Error with cert at depth: %d\n", depth);

    X509_NAME_oneline(X509_get_issuer_name(cert), data, sizeof(data));
    fprintf(stderr, " issuer = %s\n", data);

    X509_NAME_oneline(X509_get_subject_name(cert), data, sizeof(data));
    fprintf(stderr, " subject = %s\n", data);

    fprintf(stderr, "err: [%d] %s\n", err, X509_verify_cert_error_string(err));
  }

  return ok;
}

SSL_CTX* setup_ssl_client_ctx(void)
{
  SSL_CTX* ctx;

  ctx = SSL_CTX_new(SSLv23_method());
  if (SSL_CTX_load_verify_locations(ctx, ADDITIONAL_TRUSTED_CA_BUNDLE_PATH, NULL) != 1)
  {
    fprintf(stderr, "Could not additional trusted certificates at %s\n", ADDITIONAL_TRUSTED_CA_BUNDLE_PATH);
  }

  if (SSL_CTX_set_default_verify_paths(ctx) != 1)
  {
    fprintf(stderr, "Could not load default trusted ca files and dirs");
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, ssl_verify_cert_callback);
  SSL_CTX_set_verify_depth(ctx, 4);

  return ctx;
}

int seed_prng(int bytes)
{
  if (!RAND_load_file("/dev/urandom", bytes))
    return 0;

  return 1;
}

int main(int argc, char* argv[])
{
  cmd_line_options_t    cmd_line_options;
  BIO*                  bio_conn = NULL;
  SSL*                  ssl = NULL;
  SSL_CTX*              ssl_ctx = NULL;
  int                   ssl_connect_ret = 0;
  char                  head_http_req_buffer[HTTP_BUFFER_SIZE];
  char                  http_res_buffer[HTTP_BUFFER_SIZE];
  int                   nb_bytes_read = 0;

  if (!parse_cmd_line_options(argc, argv, &cmd_line_options))
  {
    print_usage();
    return 1;
  }

  init_openssl();
  ssl_ctx = setup_ssl_client_ctx();

  char port_str[MAX_TCP_PORT_STR_LENGTH];
  snprintf(port_str, MAX_TCP_PORT_STR_LENGTH, "%d", DEFAULT_HTTPS_PORT);

  // + 2 to account for the ":" and \0 characters
  size_t host_and_port_str_length = strlen(cmd_line_options.server_host_name) + strlen(port_str) + 2;
  char* host_and_port_str = malloc(host_and_port_str_length * sizeof(char));
  if (!host_and_port_str)
  {
    fprintf(stderr, "Could not allocate memory for host and port string, aborting.");
    return 1;
  }
  snprintf(host_and_port_str, host_and_port_str_length, "%s:%d", cmd_line_options.server_host_name, DEFAULT_HTTPS_PORT);

  fprintf(stdout, "Connecting to: %s...\n", host_and_port_str);
  bio_conn = BIO_new_connect(host_and_port_str);
  if (!bio_conn)
  {
    fprintf(stderr, "Error creating connection BIO, aborting\n");
    return 1;
  }

  if (BIO_do_connect(bio_conn) <= 0)
  {
    fprintf(stderr, "Error connecting to remote host, aborting\n");
    return 1;
  }

  printf("Initializing SSL engine...\n");
  ssl = SSL_new(ssl_ctx);
  if (!ssl)
  {
    fprintf(stderr, "Error while creating SSL context, aborting");
    return 1;
  }

  printf("Setting BIO for SSL engine...\n");
  SSL_set_bio(ssl, bio_conn, bio_conn);

  printf("Performing SSL handshake...\n");
  if ((ssl_connect_ret = SSL_connect(ssl)) <= 0)
  {
    fprintf(stderr, "Error during SSL handshake, reason: %d, aborting", SSL_get_error(ssl, ssl_connect_ret));
    return 1;
  }

  snprintf(head_http_req_buffer, HTTP_BUFFER_SIZE,
           "HEAD / HTTP/1.%s\r\nHost: %s\r\n"\
           "Cache-Control: no-cache\r\n\r\n",
           "1", cmd_line_options.server_host_name);
  fprintf(stdout, "Request sent:\n%s", head_http_req_buffer);

  if (SSL_write(ssl, head_http_req_buffer, strlen(head_http_req_buffer)) <= 0)
  {
    fprintf(stderr, "Could not send HEAD request, aborting");
    return 1;
  }

  if ((nb_bytes_read = (SSL_read(ssl, http_res_buffer, HTTP_BUFFER_SIZE))) <= 0)
  {
    fprintf(stderr, "Could not read response to HEAD request, aborting");
    return 1;
  }

  http_res_buffer[nb_bytes_read] = '\0';
  fprintf(stdout, "Response:\n%s", http_res_buffer);

  printf("Shutting down SSL...\n");
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  printf("SSL shutdown completed.\n");

  return 0;
}

