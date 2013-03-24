/*
 * eap_chbind.c
 *
 * Version:     $Id$
 *
 * Copyright (c) 2012, JANET(UK)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS 
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include "eap_chbind.h"

#define MAX_PACKET_LEN		4096

/*
 * Process any channel bindings included in the request.
 */
CHBIND_REQ *chbind_allocate(void)
{
  CHBIND_REQ *ret;
  ret = malloc(sizeof *ret);
  if (0 != ret)
    memset(ret, 0, sizeof *ret);
  return ret;
}

void chbind_free(CHBIND_REQ *chbind)
{
  /* free the chbind response, if allocated by chbind_process */
  if (chbind->chbind_resp)
    free(chbind->chbind_resp);

  free(chbind);
}

int chbind_process(REQUEST *req, CHBIND_REQ *chbind_req)
{
  int rcode = PW_AUTHENTICATION_REJECT;
  REQUEST *fake = NULL;
  VALUE_PAIR *vp = NULL;
  uint8_t *attr_data;
  size_t datalen = 0;

  /* check input parameters */
  rad_assert((req != NULL) && 
	     (chbind_req != NULL) &&
	     (chbind_req->chbind_req_pkt != NULL));
  if (chbind_req->chbind_req_len < 4)
    return PW_AUTHENTICATION_REJECT;  /* Is this the right response? */

  /* Set-up NULL response for cases where channel bindings can't be processed */
  chbind_req->chbind_resp = NULL;
  chbind_req->chbind_resp_len = 0;

  /* Set-up the fake request */
  fake = request_alloc_fake(req);
  rad_assert(fake->packet->vps == NULL);
  vp = pairmake("Freeradius-Proxied-To", "127.0.0.1", T_OP_EQ);
  if (vp) {
    pairadd(&fake->packet->vps, vp);
  }
  
  /* Add the username to the fake request */
  if (chbind_req->username) {
    vp = paircreate(PW_USER_NAME, 0);
    rad_assert(vp);
    memcpy(vp->vp_octets, chbind_req->username, chbind_req->username_len);
    vp->length = chbind_req->username_len;

    pairadd(&fake->packet->vps, vp);
    fake->username = pairfind(fake->packet->vps, PW_USER_NAME, 0, TAG_ANY);
  }

  /* Copy the request state into the fake request */
  /*xxx vp = paircopy(req->state);
  if (vp)
  pairadd(&fake->packet->vps, vp);*/

  /* Add the channel binding attributes to the fake packet */
  if (0 != (datalen = chbind_get_data((CHBIND_PACKET_T *)chbind_req->chbind_req_pkt, 
				      chbind_req->chbind_req_len, 
				      CHBIND_NSID_RADIUS, &attr_data))) {
	  while(datalen > 0) {
		  int mylen = rad_attr2vp(NULL, NULL, NULL, attr_data, datalen, &vp);
		  if (mylen <= 0) {
			  /* If radaddr2vp fails, return NULL string for 
			     channel binding response */
			  request_free(&fake);
			  return PW_AUTHENTICATION_ACK;
		  }
		  /* TODO: need to account for the possibility of rad_attr2vp generating 
		     multiple vps */
		  if (vp)
			  pairadd(&fake->packet->vps, vp);
		  attr_data += mylen;
		  datalen -= mylen;
	  }
  }

  /* Set virtual server based on configuration for channel bindings,
     this is hard-coded to "chbind" for now */
  fake->server = "chbind";

  /* Call rad_authenticate */
  if ((debug_flag > 0) && fr_log_fp) {
	  DEBUG("prcoessing chbind request");

	  debug_pair_list(fake->packet->vps);

	  fprintf(fr_log_fp, "server %s {\n",
	    (fake->server == NULL) ? "" : fake->server);
  }
  rcode = rad_authenticate(fake);

  switch(rcode) {
    /* If rad_authenticate succeeded, build a reply */
  case RLM_MODULE_OK:
  case RLM_MODULE_HANDLED:
    if ((chbind_req->chbind_resp = chbind_build_response(fake, &chbind_req->chbind_resp_len)) != NULL)
      rcode = PW_AUTHENTICATION_ACK;
    else
      rcode = PW_AUTHENTICATION_REJECT;
    break;
  
  /* If we got any other response from rad_authenticate, it maps to a reject */
  default:
    rcode = PW_AUTHENTICATION_REJECT;
    break;
  }

  request_free(&fake);

  return rcode;
}

/*
 * Parse channel binding packet to obtain data for a specific NSID.
 * See http://tools.ietf.org/html/draft-ietf-emu-chbind-13#section-5.3.2:
 */ 

size_t chbind_get_data(CHBIND_PACKET_T *chbind_packet,
			   size_t chbind_packet_len,
			   int desired_nsid,
			   uint8_t **radbuf_data)
{
  size_t chbind_data_len = chbind_packet_len-1;
  size_t pos=0;
  if (chbind_packet->code != CHBIND_CODE_REQUEST)
    return 0;
  while (pos + 3 < chbind_data_len) {
    size_t len = (chbind_packet->data[pos] << 8) + 
      chbind_packet->data[pos + 1];
    uint8_t nsid = chbind_packet->data[pos + 2];
    if (pos + 3 > chbind_data_len + len) {
      /* malformed packet; warn here */
      return 0;
    }
    if (nsid == desired_nsid) {
      *radbuf_data = &chbind_packet->data[pos+3];
      return len;
    }
    pos += 3 + len;
  }
  /* didn't find any data matching nsid */
  if (pos != chbind_data_len) {
    /* warn about malformed packet */
  }

  return 0;
}

uint8_t *chbind_build_response(REQUEST *req, size_t *resp_len)
{
  uint8_t *resp;
  uint16_t rlen, len = 0;
  VALUE_PAIR *vp = NULL;

  *resp_len = 0;
  resp = malloc(MAX_PACKET_LEN + 4);
  rad_assert(resp);

  /* Set-up the chbind header fields (except length, computed later) */
  vp = pairfind(req->config_items, PW_CHBIND_RESPONSE_CODE, 0, TAG_ANY);
  if (vp)
    resp[0] = vp->vp_integer;
  else resp[0] = 3; /*failure*/
  

  resp[3] = CHBIND_NSID_RADIUS;

  if ((debug_flag > 0) && fr_log_fp) {
	  DEBUG("Sending chbind response: code %i\n", (int )(resp[0]));
	  debug_pair_list(req->reply->vps);
	  DEBUG("end chbind response\n");
  }
  /* Encode the chbind attributes into the response */
  for (vp = req->reply->vps, rlen = 4; 
       (vp != NULL) && (rlen < MAX_PACKET_LEN + 4); 
       rlen += len) {
    len = rad_vp2attr(NULL, NULL, NULL, (const VALUE_PAIR **) &vp, &resp[rlen], (MAX_PACKET_LEN + 4) - rlen);
  }

  /* Write the length field into the header */
  resp[1] = (uint8_t)(rlen >> 8);
  resp[2] = (uint8_t)(rlen & 0x00FF);
  
  /* Output the length of the entire response (attrs + header) */
  *resp_len = rlen + 4;

  return resp;
}
