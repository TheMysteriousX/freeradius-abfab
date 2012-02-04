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

#ifndef _EAP_CHBIND_H
#define _EAP_CHBIND_H

#include <freeradius-devel/ident.h>
RCSIDH(eap_chbind_h, "$Id$")

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>

#include <freeradius-devel/radiusd.h>

#include "eap.h"

/* Structure to hold channel bindings req/resp information */
typedef struct CHBIND_REQ {
  uint8_t       *username;		/* the username */
  size_t        username_len;           /* length of the username */
  uint8_t	*chbind_req_pkt;            /* channel binding request buffer */
  size_t	chbind_req_len;         /* length of the request buffer */
  uint8_t       *chbind_resp;           /* channel binding response buffer */
  size_t        chbind_resp_len;        /* length of the response buffer */
} CHBIND_REQ;

/* Structure to represent eap channel binding packet format */
typedef struct chbind_packet_t {
  uint8_t code;
  uint8_t data[1];
} CHBIND_PACKET_T;

/* Protocol constants */
#define CHBIND_NSID_RADIUS		1

#define CHBIND_CODE_REQUEST		1
#define CHBIND_CODE_SUCCESS             2
#define CHBIND_CODE_FAILURE             3

/* Channel binding function prototypes */
CHBIND_REQ *chbind_allocate(void);
void chbind_free(CHBIND_REQ *chbind);
int chbind_process(REQUEST *req, CHBIND_REQ *chbind_req);
size_t chbind_get_data(CHBIND_PACKET_T *chbind_packet, size_t chbind_packet_len, int desired_nsid, uint8_t **radbuf_data);
uint8_t *chbind_build_response(REQUEST *req, size_t *resp_len);

#endif /*_EAP_CHBIND_H*/
