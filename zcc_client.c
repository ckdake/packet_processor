/*
 *
 */

#include <stdlib.h>
#include <stdio.h>

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/client.h>

#define NAME       "ZCC XML-RPC Client"
#define VERSION    "1.0"
#define SERVER_URL "http://localhost:8080/KeyService.php"

static void die_if_fault_occurred (xmlrpc_env* env) {
  if (env->fault_occurred) {
    fprintf(stderr,
            "XML-RPC Fault: %s (%d)\n",
            env->fault_string,
            env->fault_code);
    exit(1);
  }
}

int main(int argc, const char ** argv) {

  xmlrpc_env env;
  xmlrpc_server_info * server;
  xmlrpc_value * result;    
  const char* key;
    
  if (argc - 1 > 0) {
    fprintf(stderr, "There are no arguments. You specified %d", argc - 1);
    exit(1);
  }

  /* Start up our XML-RPC client library. */
  xmlrpc_client_init(XMLRPC_CLIENT_NO_FLAGS, NAME, VERSION);
  xmlrpc_env_init(&env);

  /* Make a new object to represent our XML-RPC server. */
  server = xmlrpc_server_info_new(&env, SERVER_URL);
  die_if_fault_occurred(&env);

  /* Set up our authentication information. */
  xmlrpc_server_info_set_basic_auth(&env, server, "jrandom", "secret");
  die_if_fault_occurred(&env);

  result = xmlrpc_client_call_server(&env, server, "zcc.getkey", "(ss)", (const char*) argv[0], (const char*) argv[1]);
  die_if_fault_occurred(&env);

  /* Dispose of our server object. */
  xmlrpc_server_info_free(server);
    
  /* Get the authentication information and print it out. */
  xmlrpc_read_string(&env, result, &key);
  die_if_fault_occurred(&env);
  printf("The key is %d\n", key);
    
  /* Dispose of our result value. */
  xmlrpc_DECREF(result);

  /* Shut down our XML-RPC client library. */
  xmlrpc_env_clean(&env);
  xmlrpc_client_cleanup();

  return 0;
}
