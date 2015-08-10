#include <stdio.h>

#include <openssl/ssl.h>

#define ADDITIONAL_TRUSTED_CA_BUNDLE_PATH       "../certs/go_daddy_ca_bundle.pem"
#define HTTP_BUFFER_SIZE                        1024

int init_openssl(void)
{
  SSL_load_error_strings();
  SSL_library_init();

  if (seed_prng(128))
    return -1;

  return 0;
}

typedef struct cmd_line_options {
  char* server_host_name;
  int secure;
} cmd_line_options_t;

void print_usage(void)
{
  fprintf(stderr, "Usage:\n"\
          "ssl-client [-s] [--secure] host:port\n");
}

int parse_cmd_line_options(int argc, char* argv[], cmd_line_options_t* res)
{
  int curr_argc = 1;

  if (argc < 2)
  {
    return -1;
  }

  while (curr_argc < argc) {
    if (!strncmp(argv[curr_argc], "-s", strlen("-s")) ||
        !strncmp(argv[curr_argc], "--secure", strlen("--secure"))) {
      res->secure = 1;
    } else {
      res->server_host_name = strdup(argv[curr_argc]);
    }

    ++curr_argc;
  }

  if (res->server_host_name == NULL)
    return -1;

  return 0;
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
    fprintf(stderr, "Could not additional trusted certificates at %s\n",
      ADDITIONAL_TRUSTED_CA_BUNDLE_PATH);
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
    return -1;

  return 0;
}

int main(int argc, char* argv[])
{
  cmd_line_options_t    cmd_line_options;
  BIO*                  bio = NULL;
  SSL_CTX*              ssl_ctx = NULL;
  int                   ssl_connect_ret = 0;
  char                  head_http_req_buffer[HTTP_BUFFER_SIZE];
  char                  http_res_buffer[HTTP_BUFFER_SIZE];
  int                   nb_bytes_read = 0;

  memset(&cmd_line_options, 0, sizeof(cmd_line_options));

  if (parse_cmd_line_options(argc, argv, &cmd_line_options))
  {
    print_usage();
    return 1;
  }

  if (init_openssl()) {
    fprintf(stderr, "Could not initialize OpenSSL, exiting.");
    return 1;
  }

  ssl_ctx = setup_ssl_client_ctx();

  if (!cmd_line_options.secure) {
    printf("Creating plain connection...\n");
    bio = BIO_new(BIO_s_connect());
    if (!bio)
    {
      fprintf(stderr, "Error creating connection BIO, exiting\n");
      return 1;
    }
  } else {
    printf("Creating SSL connection...\n");
    bio = BIO_new_ssl_connect(ssl_ctx);
  }

  BIO_set_conn_hostname(bio, cmd_line_options.server_host_name);

  fprintf(stdout, "Connecting to: %s...\n", cmd_line_options.server_host_name);
  if (BIO_do_connect(bio) <= 0)
    {
      fprintf(stderr, "Error connecting to remote host, exiting\n");
      return 1;
    }

  snprintf(head_http_req_buffer, HTTP_BUFFER_SIZE,
           "HEAD / HTTP/1.%s\r\nHost: %s\r\n"\
           "Cache-Control: no-cache\r\n\r\n",
           "1", cmd_line_options.server_host_name);
  fprintf(stdout, "Request sent:\n%s", head_http_req_buffer);

  if (BIO_write(bio, head_http_req_buffer, strlen(head_http_req_buffer)) <= 0)
  {
    fprintf(stderr, "Could not send HEAD request, exiting\n");
    return 1;
  }

  if ((nb_bytes_read = (BIO_read(bio, http_res_buffer, HTTP_BUFFER_SIZE))) <= 0)
  {
    fprintf(stderr, "Could not read response to HEAD request, exiting\n");
    return 1;
  }

  http_res_buffer[nb_bytes_read] = '\0';
  fprintf(stdout, "Response:\n%s", http_res_buffer);

  BIO_free_all(bio);
  SSL_CTX_free(ssl_ctx);
  printf("SSL shutdown completed.\n");

  return 0;
}

