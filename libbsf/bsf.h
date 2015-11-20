/*
*
* Copyright 2008-2009 Lockheed Martin Corporation
* 
* The libBSF program is open source software: you can copy it, redistribute it and/or modify
* it under the terms of the GNU General Public License version 2.0 as published by
* the Free Software Foundation.  The libBSF Program and any derivatives of the libBSF program 
* must be licensed under GPL version 2.0 and may not be licensed under GPL version 3.0.
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY OF ANY KIND, including without limitation the implied warranties of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details at http://www.gnu.org/licenses/gpl-2.0.html.
* 
* The term "libBSF" should be taken to also include any portions or derived works of libBSF.  
* 
* You are highly encouraged to send your changes to the Vortex program to 
* opensource.tools.security@lmco.com for possible incorporation into the main distribution.  
* By sending these changes to Lockheed Martin, you are granting to Lockheed Martin 
* Corporation the unlimited, perpetual, non-exclusive right to reuse, modify, 
* and/or relicense the code on a royalty-free basis.
* 
* The libraries to which libBSF links are distributed under the terms of their own licenses.  
* Please see those libraries for their applicable licenses.
*
*/
/*
*
* libbsf a stream filtering mechanism based on BPF and tcpdump filter syntax
* 
*/

#ifndef _BSF_BSF_H
#define _BSF_BSF_H

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <pcap-bpf.h>


#define BSF_ERROR_NONE 0
#define BSF_ERROR_PCAP_OPEN 1
#define BSF_ERROR_MALLOC 2
#define BSF_ERROR_FILTER 3

#define BSF_FLAG_NO_OPTIMIZE 1
#define BSF_FLAG_NO_TRANSLATE 2
#define BSF_FLAG_VALIDATE 4

#define BSF_RESULT_PASS 0
#define BSF_RESULT_FAIL 1
#define BSF_RESULT_ERROR 2

struct bsf {
	unsigned int flags;
	struct bpf_program *bpf_prog;
};

typedef struct bsf bsf_t;

//Used to create a new BSF. Must be freed with bsf_destroy
bsf_t *bsf_create();

//Used to comple a BSF with the given filter and flags
int bsf_compile(bsf_t *bsf_desc, char *filter, int flags);

//Free a previously created bsf
void bsf_destroy(bsf_t *bsf_desc);

//Actually filter a connection
int bsf_filter(bsf_t *bsf_desc, in_addr_t clt_ip, in_port_t clt_port, in_addr_t svr_ip, in_port_t svr_port);



#endif  //_BSF_BSF_H

