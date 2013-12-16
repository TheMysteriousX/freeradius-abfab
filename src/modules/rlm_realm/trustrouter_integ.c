#include <trust_router/tid.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include "trustrouter_integ.h"
#include <trust_router/tr_dh.h>
#include <freeradius-devel/realms.h>

static TIDC_INSTANCE *global_tidc = NULL;


struct resp_opaque {
  REALM *output_realm;
  TID_RC result;
  char err_msg[1024];
};


int tr_init(void) 
{
  if (NULL == (global_tidc = tidc_create())) {
    fprintf(stderr, "tr_init: Error creating global TIDC instance.\n");
    return -1;
  }
  if (NULL == (global_tidc->client_dh = tr_create_dh_params(NULL, 0))) {
    fprintf(stderr, "tr_init: Error creating client DH params.\n");
    return 1;
  }
  return 0;
}

static fr_tls_server_conf_t *construct_tls( TIDC_INSTANCE *inst,
					    home_server *hs,
					    TID_SRVR_BLK *server)
{
  fr_tls_server_conf_t *tls = talloc_zero( hs, fr_tls_server_conf_t);
  unsigned char *key_buf = NULL;
  ssize_t keylen;
  char *hexbuf = NULL;
  char *psk_identity = NULL;
  int i;

  if (tls == NULL)
    goto error;
  keylen = tr_compute_dh_key(&key_buf, server->aaa_server_dh->pub_key,
			     inst->client_dh);
  if (keylen <= 0) {
    DEBUG2("DH error");
    goto error;
  }
  hexbuf = talloc_size(tls, keylen*2 + 1);
  if (hexbuf == NULL)
    goto error;
  tr_bin_to_hex(key_buf, keylen, hexbuf,
	     2*keylen + 1);
  tls->psk_password = hexbuf;
  psk_identity = tr_name_strdup(server->key_name);
  if (psk_identity == NULL) {
    goto error;
  } else {
    tls->psk_identity = talloc_strdup(tls, psk_identity);
    free(psk_identity);
  }
  if (tls->psk_identity == NULL)
    goto error;

  fprintf (stderr, "construct_tls: Client key generated (key name = %s):\n", tls->psk_identity);
  for (i = 0; i < keylen; i++) {
    printf("%.2x", key_buf[i]); 
  }
  printf("\n");

  tls->cipher_list = talloc_strdup(tls, "PSK");
  if (tls->cipher_list == NULL)
    goto error;
  tls->fragment_size = 4200;
  tls->ctx = tls_init_ctx(tls, 1);
  if (tls->ctx == NULL)
    goto error;
  memset(key_buf, 0, keylen);
  free(key_buf);
    return tls;
 error:
    if (key_buf) {
      memset(key_buf, 0, keylen);
      free(key_buf);
    }
    if (hexbuf) {
      memset(hexbuf, 0, keylen*2);
    }
    if (tls)
      talloc_free(tls);
    return NULL;
}
  
static void tr_response_func( TIDC_INSTANCE *inst,
			     UNUSED TID_REQ *req, TID_RESP *resp,
			     void *cookie)
{
  home_server *hs = NULL;
  TID_SRVR_BLK *server;
  home_pool_t *pool = NULL;
  REALM *nr = NULL;
  char home_pool_name[256];
  int pool_added = 0;
  fr_ipaddr_t home_server_ip;
  struct resp_opaque  *opaque = (struct resp_opaque *) cookie;
  size_t num_servers = 0;

  /*xxx There's a race if this is called in two threads for the
    same realm. Imagine if the home pool is not found in either
    thread, is inserted in one thread and then the second
    thread's insert fails. The second thread will fail. Probably
    not a huge deal because a retransmit will make the world
    great again.*/
  if (resp->result != TID_SUCCESS) {
    size_t err_msg_len;
    opaque->result = resp->result;
    memset(opaque->err_msg, 0, sizeof(opaque->err_msg));
    if (resp->err_msg) {
      err_msg_len = resp->err_msg->len+1;
      if (err_msg_len > sizeof(opaque->err_msg))
	err_msg_len = sizeof(opaque->err_msg);
      strlcpy(opaque->err_msg, resp->err_msg->buf, err_msg_len);
    }
    return;
  }
  server = resp->servers;
  while (server) {
    num_servers++;
    server = server->next;
  }
  strlcpy(home_pool_name, "hp-", sizeof(home_pool_name));
  tr_name_strlcat(home_pool_name, resp->realm, sizeof(home_pool_name));
  pool = home_pool_byname(home_pool_name, HOME_TYPE_AUTH);
  if (pool == NULL) {
    size_t i = 0;
    pool = talloc_size(NULL, sizeof(*pool) + num_servers *sizeof(home_server *));
		  
    if (pool == NULL) goto error;
    memset(pool, 0, sizeof(*pool));
    pool->type = HOME_POOL_CLIENT_PORT_BALANCE;
    pool->server_type = HOME_TYPE_AUTH;
    pool->name = talloc_strdup(pool, home_pool_name);
    if (pool->name == NULL) goto error;
    pool->num_home_servers = num_servers;

    server = resp->servers;
    while (server) {
      home_server_ip.af = AF_INET;
      home_server_ip.scope = 0;
      home_server_ip.ipaddr.ip4addr = server->aaa_server_addr;
	  
      hs = home_server_find( &home_server_ip, 2083,
			     IPPROTO_TCP);
      if (hs) {
	DEBUG2("Found existing home_server %s", hs->name);
      } else {
	char nametemp[INET_ADDRSTRLEN];
	inet_ntop(home_server_ip.af, &home_server_ip.ipaddr, nametemp, sizeof(nametemp));
	hs = talloc_zero(pool, home_server);
	if (!hs) return;
	memset(hs, 0, sizeof(*hs));
	hs->type = HOME_TYPE_AUTH;
	hs->ipaddr = home_server_ip;
        hs->src_ipaddr.af = home_server_ip.af;
	hs->name = talloc_strdup(hs, nametemp);
	hs->hostname = talloc_strdup(hs, nametemp);
	  hs->port = 2083;
	hs->proto = IPPROTO_TCP;
	hs->secret = talloc_strdup(hs, "radsec");
	hs->tls = construct_tls(inst, hs, server);
	if (hs->tls == NULL) goto error;
	if (!realms_home_server_add(hs, NULL, 0))
	  goto error;
      }
      pool->servers[i++] = hs;
      hs = NULL;
      server = server->next;
    }
			
    if (!realms_pool_add(pool, NULL)) goto error;
    pool_added = 1;
  }
		
  nr = rad_malloc(sizeof (REALM));
  if (nr == NULL) goto error;
  memset(nr, 0, sizeof(REALM));
  nr->name = tr_name_strdup(resp->realm);
  nr->auth_pool = pool;
  if (!realms_realm_add(nr, NULL)) goto error;
  opaque->output_realm = nr;
		
		
  return;
		
 error:
  if (hs)
    talloc_free(hs);
  if (pool && (!pool_added)) {
    talloc_free(pool);
  }
  if (nr)
    free(nr);
  return;
}
		

REALM *tr_query_realm(const char *q_realm,
		      const char  *q_community,
		      const char *q_rprealm,
		      const char *q_trustrouter)
{
  int conn = 0;
  int rc;
  gss_ctx_id_t gssctx;
  struct resp_opaque *cookie;

  /* clear the cookie structure */
  cookie = malloc(sizeof(struct resp_opaque));
  memset (cookie, 0, sizeof(struct resp_opaque));

  /* Set-up TID connection */
  if (-1 == (conn = tidc_open_connection(global_tidc, (char *)q_trustrouter, &gssctx))) {
    /* Handle error */
    printf("Error in tidc_open_connection.\n");
    return NULL;
  };

  /* Send a TID request */
  if (0 > (rc = tidc_send_request(global_tidc, conn, gssctx, (char *)q_rprealm, 
				  (char *) q_realm, (char *)q_community, 
				  &tr_response_func, cookie))) {
    /* Handle error */
    printf("Error in tidc_send_request, rc = %d.\n", rc);
    return NULL;
  }

  return cookie->output_realm;
}
