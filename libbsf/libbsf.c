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
 * compile:
 * gcc -Wall -fPIC -shared libbsf.c -o libbsf.so
 * install:
 * copy bsf.h to your include dir (/usr/include)
 * copy libbsf.so to your lib dir (/usr/lib) or (/usr/lib64)
 */



#include <stdlib.h>
#include "bsf.h"


#define BSF_SNAP_LEN (BSF_LINK_LEN + BSF_IP_LEN + BSF_TCP_LEN)
#define BSF_LINK_LEN 0
#define BSF_IP_LEN 20
#define BSF_TCP_LEN 4

#define BSF_LINK_TYPE DLT_RAW
#define BSF_WHITE_SPACE "()\t\n "




//returns 0 if char is not contained in white_space string, 1 if it is
int is_white_space(char *white_space, char c)
{
    if ( strchr(white_space, c) == NULL)
    {
        return 0;
    } else
    {
        return 1;
    }
}

//replace all instances of to_replace in filter which are bounded by one of the characters in white_space with replacement
//returns 0 on normal, else on error
int word_replace(char *filter, char *white_space, char *string_to_replace, char *string_replacement)
{
    //some basic validation
    if (strlen(string_replacement) != strlen(string_to_replace))
    {
        return 1;
    }
    if (strlen(string_to_replace) < 1)
    {
        return 1;
    }	


    char *filter_current_pos;
    char *filter_current_match;

    int i;

    filter_current_pos = filter;

    while((filter_current_match = strstr(filter_current_pos,string_to_replace)))
    {

        //check to see if previous char is white space
        //special case for match at first char
        if ((is_white_space(white_space, filter[strlen(filter)-strlen(filter_current_match)-1])) || (filter_current_match == filter))
        {
            //now try for white space after hit
            //special case for hit that contains last car
            if( (is_white_space(white_space, filter_current_match[strlen(string_to_replace)])) || (strlen(filter_current_match) == strlen(string_to_replace)) )
            {
                //the word is surrounded by white space, replace it
                for (i = 0; i < strlen(string_to_replace); i++)
                {
                    filter[strlen(filter)-strlen(filter_current_match)+i] = string_replacement[i];
                }
            }	
        }
        filter_current_pos = &filter_current_match[1];
    }
    return 0;
}


void translate_filter(char *filter)
{
    word_replace(filter, BSF_WHITE_SPACE, "clt", "src");
    word_replace(filter, BSF_WHITE_SPACE, "svr", "dst");
}


//creates a new BSF. 
bsf_t *bsf_create()
{
    return calloc(1,sizeof(bsf_t));
}


//Compile the specified filter into the previously created (non-null) bsf using specified flags
int bsf_compile(bsf_t *bsf_desc, char *filter, int flags)
{
    pcap_t	*pcap_desc;
    struct bpf_program *bpf_prog;
    int optimize;
    int translate;
    char *bpf_filter;
    //bsf_t *bsf_desc;

    //modify this if we do translation
    bpf_filter = filter;


    //process the pertinant flags
    //optimize
    if (flags & BSF_FLAG_NO_OPTIMIZE)
    {
        optimize = 0;
    } else
    {
        optimize = 1;
    }

    //translate
    if (flags & BSF_FLAG_NO_TRANSLATE)
    {
        translate = 0;
    } else
    {
        translate = 1;
    }




    //try to create pcap descriptor
    pcap_desc = pcap_open_dead(BSF_LINK_TYPE, BSF_SNAP_LEN);
    if (pcap_desc == NULL)
    {
        //	free(bsf_desc);
        return BSF_ERROR_PCAP_OPEN;
    }

    //Malloc a bpf_program
    bpf_prog = calloc(1,sizeof(struct bpf_program));
    if (bpf_prog == NULL)
    {
        //	free(bsf_desc);
        pcap_close(pcap_desc);
        return BSF_ERROR_MALLOC;
    }

    //create a copy of the input filter so we can translate it.
    bpf_filter = calloc(1,strlen(filter)+1);
    if (bpf_filter == NULL)
    {
        //	free(bsf_desc);
        pcap_close(pcap_desc);
        free(bpf_prog);
        return BSF_ERROR_MALLOC;
    }

    strncpy( bpf_filter, filter, strlen(filter));

    //run filter translation routines
    if (translate)
    {
        translate_filter(bpf_filter);		
    }	

    if (pcap_compile(pcap_desc, bpf_prog, bpf_filter, optimize, 0) == -1)
    {
        //	free(bsf_desc);
        pcap_close(pcap_desc);
        free(bpf_prog);
        free(bpf_filter);
        return BSF_ERROR_FILTER;

        //we don't do anything with error message, but we could--use pcap_geterr(pcap_desc) to retrieve it.

    }

    bsf_desc->bpf_prog = bpf_prog;
    bsf_desc->flags = flags;
    //*bsf_desc_ref = bsf_desc;

    free(bpf_filter);
    pcap_close(pcap_desc);
    return BSF_ERROR_NONE;
}

void bsf_destroy(bsf_t *bsf_desc)
{
    pcap_freecode(bsf_desc->bpf_prog);
    free(bsf_desc->bpf_prog);
    free(bsf_desc);
    return;
}



//Used to populate create a minimalistic ethernet/ip/tcp packet
void populate_packet(unsigned char *packet, in_addr_t clt_ip, in_port_t clt_port, in_addr_t svr_ip, in_port_t svr_port)
{
    //this is just easier than setting zeros everywehere necessary
    //bzero(packet, BSF_SNAP_LEN);
    unsigned int temp;

    //Hardcoded constants


    //set IP version and hdr len
    packet[BSF_LINK_LEN] = 0x45;
    //set IP total length
    packet[BSF_LINK_LEN+2] = 0x00;
    packet[BSF_LINK_LEN+3] = 0x1C;
    //set IP prototol (TCP)
    packet[BSF_LINK_LEN+9] = 0x06;

    //set UDP/TCP hdr len
    //packet[BSF_LINK_LEN+BSF_IP_LEN+8] = 0x20;

    //Set per stream values

    //src ip
    temp = clt_ip & 0xFF;
    packet[BSF_LINK_LEN + 12] = temp;
    temp = clt_ip & 0xFF00;
    temp >>= 8;
    packet[BSF_LINK_LEN + 13] = temp;
    temp = clt_ip & 0xFF0000;
    temp >>= 16;
    packet[BSF_LINK_LEN + 14] = temp;
    temp = clt_ip & 0xFF000000;
    temp >>= 24;
    packet[BSF_LINK_LEN + 15] = temp;


    //dst ip

    temp = svr_ip & 0xFF;
    packet[BSF_LINK_LEN + 16] = temp;
    temp = svr_ip & 0xFF00;
    temp >>= 8;
    packet[BSF_LINK_LEN + 17] = temp;
    temp = svr_ip & 0xFF0000;
    temp >>= 16;
    packet[BSF_LINK_LEN + 18] = temp;
    temp = svr_ip & 0xFF000000;
    temp >>= 24;
    packet[BSF_LINK_LEN + 19] = temp;



    //src port
    temp = clt_port & 0xFF;
    packet[BSF_LINK_LEN+BSF_IP_LEN+1] = temp;
    temp = clt_port & 0xFF00;
    temp >>= 8;
    packet[BSF_LINK_LEN+BSF_IP_LEN] = temp;

    //dst port
    temp = svr_port & 0xFF;
    packet[BSF_LINK_LEN+BSF_IP_LEN+3] = temp;
    temp = svr_port & 0xFF00;
    temp >>= 8;
    packet[BSF_LINK_LEN+BSF_IP_LEN+2] = temp;

}


int bsf_filter(bsf_t *bsf_desc, in_addr_t clt_ip, in_port_t clt_port, in_addr_t svr_ip, in_port_t svr_port)
{
    unsigned char dummy_packet[BSF_SNAP_LEN];


    populate_packet(dummy_packet, clt_ip, clt_port, svr_ip, svr_port);
    //validate the bpf program
    if (bsf_desc->flags && BSF_FLAG_VALIDATE == BSF_FLAG_VALIDATE)
    {
        //validate the BPF:
        if (bpf_validate(bsf_desc->bpf_prog->bf_insns, bsf_desc->bpf_prog->bf_len) == 0)
        {
            //validation failed
            return BSF_RESULT_ERROR;
        } 	
    }

    if (bpf_filter(bsf_desc->bpf_prog->bf_insns, dummy_packet, BSF_SNAP_LEN, BSF_SNAP_LEN) == BSF_SNAP_LEN)
    {
        return BSF_RESULT_PASS;
    } else
    {
        return BSF_RESULT_FAIL;
    }


}
