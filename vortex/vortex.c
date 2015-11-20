/*
*
* Copyright 2008-2011 Lockheed Martin Corporation
* 
* The Vortex program is open source software: you can copy it, redistribute it and/or modify
* it under the terms of the GNU General Public License version 2.0 as published by
* the Free Software Foundation.  The Vortex Program and any derivatives of the Vortex program 
* must be licensed under GPL version 2.0 and may not be licensed under GPL version 3.0.
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY OF ANY KIND, including without limitation the implied warranties of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details at http://www.gnu.org/licenses/gpl-2.0.html.
* 
* The term "Vortex" should be taken to also include any portions or derived works of Vortex.  
* 
* You are highly encouraged to send your changes to the Vortex program to 
* opensource.tools.security@lmco.com for possible incorporation into the main distribution.  
* By sending these changes to Lockheed Martin, you are granting to Lockheed Martin 
* Corporation the unlimited, perpetual, non-exclusive right to reuse, modify, 
* and/or relicense the code on a royalty-free basis.
* 
* The libraries to which Vortex links are distributed under the terms of their own licenses.  
* Please see those libraries for their applicable licenses.
*
*/
/*
* Vortex
* a flexible program for tcp reassembly
* compile:
* (If you have libbsf installed as shared library)
* gcc vortex.c -lnids -lpthread -lbsf -Wall -DWITH_BSF -o vortex -O2
* (If you don't have libsf)
* gcc vortex.c -lnids -lpthread -Wall -o vortex -O2
*/

#define _GNU_SOURCE

#ifdef linux
#include <syscall.h>
#endif

#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include "nids.h"
#include <pcap.h>

#ifdef WITH_BSF
#include <bsf.h>
#endif

//don't ask me why this isn't in headers?
#define gettid() syscall(__NR_gettid)
#define my_sched_setaffinity(a,b,c) sched_setaffinity(a, b, c)

//TODO LIST:

//Long Term:
//Deal with URG data?
//Extend interface to UDP? 
//Major Performance Improvements?

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))
#define VORTEX_DIRECTION_TO_SERVER 0
#define VORTEX_DIRECTION_TO_CLIENT 1
#define VORTEX_DIRECTION_TO_BOTH 2

#define VORTEX_STILL_OPEN 0
#define VORTEX_SIZE_LIMIT_REACHED 16
#define VORTEX_IDLE 17

#define REALLOC_INCREASE_PERCENT_MAX 10000

//Define some Macros for error logging
#define DEBUG(l,m...) { if (l <= debug_level) { LOG(LOG_DEBUG, m); } }
#define WARN(m...) {  LOG(LOG_WARNING, m); }
#define ERROR(m...) {  LOG(LOG_ERR, m); }
#define DIE(m...) { LOG(LOG_CRIT, m); exit(1); }
#define LOG(p,m...) { syslog(p, m); fprintf(stderr, m); fprintf(stderr, "\n"); }

//max number of chars that can be included in metadata
//this is used to ensure buffers are not overrun
//45 is max for normal metadata
//99 for extended output
#define METADATA_MAX 200


//global vars,Defaults
//for getopt
extern int optind;
extern int opterr;
extern int optopt;
extern char *optarg;
pthread_attr_t pthread_attrs;
int collection = VORTEX_DIRECTION_TO_SERVER;
char *temp_data_dir="";

//Limits for capture in both directions in bytes
size_t to_server_data_size_limit = 104857600; //100 MB
size_t to_client_data_size_limit = 104857600; //100 MB
int debug_level = 0;

unsigned long int connection_id = 0;
unsigned long int closed_connections = 0;
//connection closures by type--hopefully the sum of the following is equal to total
unsigned long int closed_connections_close = 0;
unsigned long int closed_connections_reset = 0;
unsigned long int closed_connections_timeout = 0;
unsigned long int closed_connections_idle = 0;
unsigned long int closed_connections_exit = 0;

unsigned long int closed_connections_limit = 0;
unsigned long int closed_connections_poll = 0;
unsigned long int closed_connections_bsf = 0;


unsigned long int max_connections = 0;
unsigned long int collected_bytes = 0;

unsigned long int pcap_stats_total_recv = 0;
unsigned long int pcap_stats_total_drop = 0;
u_int pcap_stats_last_recv = 0;
u_int pcap_stats_last_drop = 0;

//realloc_copy
//unsigned long int realloc_copy_count = 0;
//unsigned long int realloc_copy_bytes = 0;




int poll_rate = 1;
//for BPF
char *filter_file = NULL;
char *filter_string = NULL;
//for BSF
char *bsf_filter_file = NULL;
char *bsf_filter_string = NULL;
int bsf_enabled = 0;
char *user = NULL;
char *process_name = NULL;

//pcap options
int snap_len = 1560;
pcap_t *desc = NULL;
char pcap_err_buf[PCAP_ERRBUF_SIZE];

//error logging
struct error_stats errors;
//name for syslog
char *logging_name;
unsigned int error_interval = 0;

//pointer to libnids nids_syslog function
void (*libnids_syslog)(int, int, struct ip *, void*)= NULL;

//stats
unsigned int stats_interval = 0;

#ifdef WITH_BSF
bsf_t *bsf_desc;
#endif

//stuff related to ring buffer
//ring buffer is utilized to allow capture and reassembly thread to operate unihibited by stream writing thread.
//the whole point of using a lockless ring buffer is that we will never have to lock the capture thread waiting for the stream writing thread. As such no locks are used. Additions to ring occur in one thread and removal occurs in the other.
struct conn_param **conn_ring = NULL;
int conn_ring_head = 0;
int conn_ring_tail = 0;
int conn_ring_size = 10000;
unsigned int conn_ring_poll_interval = 10000;

//adding notion of state of vortex program run. 0 => intialization, 1 => stream collection and processing, 2 => dump remaining streams, 3 => other cleanup (wait for error and stats threads to finish, etc)
int program_state = 0;


//thread priorities--yes even vortex has priorities
int capture_prio = -15;
int other_prio = 10;
//cpu affinity--override CPU scheduling
int capture_cpu = -1;
int other_cpu = -1;
int stats_thread_init = 0;
int error_thread_init = 0;
int output_thread_init = 0;
//int cpu_locking = 0;
int extended_output = 0;

//By default open connections stay open for ever
int tcp_max_idle = -1;
struct conn_param *tcp_head;
struct conn_param *tcp_tail;

//timestampe from last packet we've processed
unsigned int last_timestamp;

int output_empty_streams = 0;

//for time stomps
int stomp_temp_file_timestamps = 0;
int disable_temp_file_stomp = 0;

//for realloc scaling
//starting size of steam buffers
//make this tunable???
size_t base_realloc_size = 4*1024;
//percentage of growth that occurs when buffer needs to grow 
unsigned int realloc_increase_percent = 100;
//multiplcation factor for buffer increase. 50% => 1.5, 100% => 2, 200% => 3
float realloc_increase_factor = 2;
//threshold above which increase isn't based on factor anymore, buffer is resized to SIZE_MAX then never increased again
size_t realloc_increase_threshold = 0;



//struct used for each connection we follow
struct conn_param
{
  struct tcp_stream *nids_stream;
  FILE *to_server_data_fp;
  FILE *to_client_data_fp;
  char *to_server_data_p;
  char *to_client_data_p;
  size_t to_server_data_size;
  unsigned int to_server_data_size_exceeded;
  size_t to_client_data_size;
  unsigned int to_client_data_size_exceeded;
  unsigned long int id;
  unsigned int start;
  unsigned int last_activity;
  struct tuple4 addr;
  char close_state;
  struct conn_param *prev_conn;
  struct conn_param *next_conn;
  size_t to_server_buffer_size;
  size_t to_client_buffer_size;
  
};


//struct of errors
struct error_stats
{
	unsigned int total;
	unsigned int ip_size;
	unsigned int ip_frag;
	unsigned int ip_hdr;
	unsigned int ip_srcrt;
	unsigned int tcp_limit;
	unsigned int tcp_hdr;
	unsigned int tcp_queue;
	unsigned int tcp_flags;
	unsigned int udp_all;
	unsigned int scan_all;
	unsigned int vtx_ring;
	unsigned int vtx_io;
	unsigned int vtx_mem;
	unsigned int other;
};


//List of every connection is maintained (to allow efficient timeouts)
//The list is ordered by last activity (NIDS_DATA) for the connection, with head pointing to most stale connection

//add connection to idle time list
void add_conn_tcp(struct conn_param *item)
{
	DEBUG(180, "Idle list add: %lu", item->id);
	
	if (tcp_head == NULL)
	{
		tcp_head = item;
		item->prev_conn = NULL;
	} else
	{
		item->prev_conn = tcp_tail;
		tcp_tail->next_conn = item;	
	}
	item->next_conn = NULL;
	tcp_tail = item;
}

//remove connection from idle time list
void rem_conn_tcp(struct conn_param *item)
{
	DEBUG(180, "Idle list rem: %lu", item->id);
	
	if (item->prev_conn == NULL)
	{
		tcp_head = item->next_conn;
	} else
	{
		item->prev_conn->next_conn = item->next_conn;
	}
	
	if (item->next_conn == NULL)
	{
		tcp_tail = item->prev_conn;
	} else
	{
		item->next_conn->prev_conn = item->prev_conn;			
	}
}

//bump connection to end of list
void bump_conn_tcp(struct conn_param *item)
{
	rem_conn_tcp(item);
	add_conn_tcp(item);
}


//return number of entries in ring
//this should be safe to call from any thread with the caveat that it is only so accurate...
int ring_entries()
{
	int conn_ring_head_cache = conn_ring_head;
	int conn_ring_tail_cache = conn_ring_tail;
	
	if (conn_ring_head_cache >= conn_ring_tail_cache)
	{
		return (conn_ring_head_cache - conn_ring_tail_cache);
	} else
	{
		return (conn_ring_size - (conn_ring_tail_cache - conn_ring_head_cache));
	}
}

//returns 1 if ring is full, 0 otherwise
//should only be called by inserting thread
int ring_full()
{
	if (conn_ring_tail == 0)
	{
		if (conn_ring_head == (conn_ring_size - 1))
		{
			return 1;
		} else
		{
			return 0;
		}
	} else
	{
		if (conn_ring_head == (conn_ring_tail - 1))
		{
			return 1;
		} else
		{
			return 0;
		}
	}
}


//return 1 if ring is empty (0 entries), 0 if it is not empty
int ring_empty()
{
	if (conn_ring_head == conn_ring_tail)
	{
		return 1;
	} else
	{
		return 0;
	}
}
//adds and entry to the ring. ring had better be intialized and not full when this is called. Obviously, only called by capture thread.
void ring_add(struct conn_param *a_conn)
{
	conn_ring[conn_ring_head] = a_conn;
	conn_ring_head++;
	if (conn_ring_head >= conn_ring_size)
	{
		conn_ring_head = 0;
	}
}

//remove conn from ring
struct conn_param *ring_remove()
{
	struct conn_param *a_conn = NULL;
	a_conn = conn_ring[conn_ring_tail];
	conn_ring_tail++;
	if (conn_ring_tail >= conn_ring_size)
	{
		conn_ring_tail = 0;
	}
	return a_conn;
}


/*
	So this funkiness deserves a little extra documentation:
	What we do here is override the nids_syslog function in libnids.c with this one (vortex_nids_syslog). That is fairly striaghtforward--libnids has provisions for it built into the api. However, if debugging is enabled, we want to call the nids_syslog function inside of this one. Herein lies funkiness. We grab the pointer to the nids_syslog function from the default nids_params struct (nids_params.syslog), save it off (as libnids_syslog), and then override it (with vortex_nids_syslog). If we do want to call libnids nids_syslog we now call libnids_syslog. 
*/
//This function overrides the libnids provided nids_syslog function. We keep counters (to be printed in a separate thread periodically) instead of printing a message for each error (unless debugging is enabled, in which we do both).
//Note that vortex errors don't call this function, they increment the counts and call DEBUG directly.
void vortex_nids_syslog(int type, int err_num, struct ip *iph, void *data)
{
	errors.total++;

	//if debug_level is above threshold, call libnids implemented nids_syslog funcation also
	if ((debug_level >= 10) && (libnids_syslog != NULL))
	{
			libnids_syslog(type, err_num, iph, data);
	}
	
	switch (type) {
    case NIDS_WARN_IP:
			if (err_num == NIDS_WARN_IP_OVERSIZED) errors.ip_size++;
		  if (err_num == NIDS_WARN_IP_INVLIST) errors.ip_frag++;
		  if (err_num == NIDS_WARN_IP_OVERLAP) errors.ip_frag++;
		  if (err_num == NIDS_WARN_IP_HDR) errors.ip_hdr++;
		  if (err_num == NIDS_WARN_IP_SRR) errors.ip_srcrt++;
		break;	
	
		case NIDS_WARN_TCP:
			if (err_num == NIDS_WARN_TCP_TOOMUCH) errors.tcp_limit++;
		  if (err_num == NIDS_WARN_TCP_HDR) errors.tcp_hdr++;
		  if (err_num == NIDS_WARN_TCP_BIGQUEUE) errors.tcp_queue++;
		  if (err_num == NIDS_WARN_TCP_BADFLAGS) errors.tcp_flags++;
		break;			  	
		
		case NIDS_WARN_UDP:
			errors.udp_all++;
		break;
		case NIDS_WARN_SCAN:
			errors.scan_all++;
		break;	
		default:
			errors.other++;
		break;
	}



}

//Available switches
//a b . . . . . . . j . . . . . . . . . . . . . . y z
//A B . . . . . . I J . . . . . . . . . . U V W X Y Z

void print_usage()
{
	fprintf(stderr,"Usage: %s [ -lpmheId ] [ -c count ] [ -i device ] [ -r file ] [ -u user ] [ -S bytes ] [ -C bytes ] [ -t dir ] [ -s count ] [ -H count ] [ -q limit ] [ -D level ] [-F file | -f filter ] [-M MTU (snaplen)] [-P poll rate] [ -TEK time ] [ -Q size ] [ -R usecs ] [ -Nn prio ] [ -Oo cpu ] [ -L name ] [ -x percent ]", process_name);
	
	#ifdef WITH_BSF
	fprintf(stderr,"[-G file | -g filter ]");
	#endif
	
	 fprintf(stderr,"\n\n");
	
	
	fprintf(stderr,
		"   -h           print this help message and exit\n"
		"   -c count     set number to connections to follow\n"
        "   -i device    listen on device\n"
        "   -r file      read capture from pcap file\n"
        "   -l           set output to line buffering\n"
        "   -p           don't put interface(s) in promiscuous mode\n"
        "   -u user      after initialization, setuid to user\n"
        "   -S bytes     number of bytes to collect from client to server Default: 104857600 (100MB)\n"
        "   -C bytes     number of bytes to collect from server to client Default: 104857600 (100MB)\n"
        "   -t dir       directory for storage of stream data (defaut: currend working dir)\n"
        "   -s count     Size of connection hash table--Maximum number of streams to follow simultaneously = 3/4 * count. Default: 1048576\n \t\t\t\t This affects memory consumption significantly. If you have problems with TCP_LIMIT, increase this value. (See n_tcp_streams in libNIDS)\n"
        "   -H count     size of IP defrag has table. Default: 65536 (See n_hosts in libNIDS)\n"
        "   -m           enable libNIDS multiprocess mode DEPRICATED--don't use this (See multiproc in libNIDS)\n"
        "   -q limit     set libNIDS packetqueue limit. DEPRICATED--only applies in multiproc mode\n"
        "   -D level     set debug level Default: 0\n"
        "   -f filter    tcpdump-style capture filter expression (don't forget quotes/shell escapes)\n"
        "   -F file      file containing packet filter expression\n"
		"   -M MTU       MTU or snaplen--maximum packet size to capture. default: 1560\n"
		"   -w           enable libNIDS TCP/IP stack workaround mode (See TCP_workarounds in libNIDS)\n"
 		"   -k           disable libNIDS TCP/IP checksum processing (See TCP_checksums in libNIDS)\n"
		"   -P rate      Only reassemble and collect every poll rate connections. default: 1\n"
		"   -T time      Report Performance Statistics every time seconds (approx) default: 0\n"
		"   -E time      Report Error counts every time seconds (approx) default: 0\n"
		"   -L name      Logging name for syslog. Default: vortex\n"
		"   -Q size      Size of output ring queue. Sets limit for number of finished streams waiting to be written. Default: 10000\n"
		"   -R usec		 Wait period in us (inverse of poll rate) for stream output thread in microseconds. Default: 10000\n"
		"   -n prio		 Priority (niceness) for capture thread. Can be from -20 to 19 on most systems. Default: -15\n"
		"   -N prio		 Priority (niceness) for other threads. Can be from -20 to 19 on most systems. Default: 10\n"
		"   -o cpu		 CPU to bind capture thread to. Negative to disable. Default: -1\n"
		"   -O cpu		 CPU to bind other threads to. Negative to disable. Default: -1\n"
		//"   -I           Lock threads to specific cores. (see o and O above). Default is to not lock so specific cores (Expiramental--still not working properly!). \n"
        "   -e           enable extended output (more metadata in file name). \n" 
        "   -K           TCP Idle connection timeout in seconds Default: -1 (disabled). This timeout ignores empty keepalives.  \n"
        "   -v           Output empty streams (create files with 0 bytes).\n"
        "   -x percent   Grow stream buffers by percent when needed. Must be 0-10000. 0 is minimum required to hold data. Default: 100.\n"
        "   -d           Disable setting timestamp of output files to that from pcap file when replaying packets.\n");
    
#ifdef WITH_BSF
		fprintf(stderr,
		"   -g filter    BSF stream filter expression (don't forget quotes/shell escapes)\n"   
		"   -G file      file containing stream filter expression\n"
		);
#endif
    
    fprintf(stderr,"   \n\n");
	
}

void flow_name(int conn_proto, unsigned long int conn_id, unsigned int conn_start, unsigned int conn_end, char conn_close_state, struct tuple4 addr, uint direction, unsigned int s_size, unsigned int c_size, char *buf)
{
	//METADATA_MAX must be updated if this is updated!
	buf[0]='\0';
	char close_state = 'c';
	if (extended_output)
	{
		if (conn_proto == 17)
		{
			sprintf (buf + strlen (buf), "udp-");
		} else
		{
			sprintf (buf + strlen (buf), "tcp-");
		}
		
		unsigned int flow_size = c_size + s_size;
		
		
		
		
		switch (conn_close_state)
    {
    	
    	case NIDS_CLOSE:
    		close_state='c';
    		break;
    	case NIDS_RESET:
    		close_state='r';
    		break;
    	case NIDS_TIMED_OUT:
    		close_state='t';
    		break;
    	case NIDS_EXITING:
    		close_state='e';
    		break;
    	case VORTEX_SIZE_LIMIT_REACHED:
    		close_state='l';
    		break;
    	case VORTEX_IDLE:
    		close_state='i';
    		break;	
		}
		
		sprintf(buf + strlen(buf), "%li-%u-%u-%c-%u-", conn_id, conn_start, conn_end, close_state, flow_size);
		
						
	}
	
	if (direction == VORTEX_DIRECTION_TO_SERVER)
		{
			strcat (buf, int_ntoa (addr.saddr));
  		sprintf (buf + strlen (buf), ":%is", addr.source);
  		strcat (buf, int_ntoa (addr.daddr));
  		sprintf (buf + strlen (buf), ":%i", addr.dest);
		} 
		else if (direction == VORTEX_DIRECTION_TO_CLIENT)
		{
			
			strcat (buf, int_ntoa (addr.saddr));
  		sprintf (buf + strlen (buf), ":%ic", addr.source);
  		strcat (buf, int_ntoa (addr.daddr));
  		sprintf (buf + strlen (buf), ":%i", addr.dest);
		} 
		else
		{
			strcat (buf, int_ntoa (addr.saddr));
  		sprintf (buf + strlen (buf), ":%i-", addr.source);
  		strcat (buf, int_ntoa (addr.daddr));
  		sprintf (buf + strlen (buf), ":%i", addr.dest);
		}
	return;
}

void data_filename(int conn_proto, unsigned long int conn_id, unsigned int conn_start, unsigned int conn_end, char conn_close_state, struct tuple4 addr, uint direction, unsigned int s_size, unsigned int c_size, char *buf)
{
	//we use a lot of "unsafe" functions here and in above. Rationale is that metadata len has hard max (see METADATA max) that can be determined in advance (max not dependent on input). Temp dir was checked to ensure it is short enough such that buffer of PATH_MAX will not be overrun, even when dir, metadata, and / separater are combined.
	int dirstr_len;
	char flow_str[METADATA_MAX]; //for flow identifier
	strcpy (buf, temp_data_dir);
	dirstr_len = strlen(buf);
	if ((dirstr_len != 0) && (buf[dirstr_len-1] != '/') )
	{
		strcat(buf + dirstr_len, "/");
	}
	flow_name(conn_proto, conn_id, conn_start, conn_end, conn_close_state, addr, direction, s_size, c_size, flow_str);
	strcat(buf,flow_str);
	return;
}

//opens file, mallocs buffer, and reads file into buffer--returns number of bytes read.
//if returns 0, buffer is not alloc'd, otherwise it is and must be freed later
//buffer is 1 byte longer than file so that buffer can be null terminated. Null char is not included in byte count returned
int read_file_into_buffer(char *filter_file, char **filter_buffer)
{
	
			FILE *filter_file_fp;
			int filter_file_len;
						
			//Open file
			filter_file_fp = fopen(filter_file, "r");
			if (!filter_file_fp)	
			{
				WARN("Couldn't open file: %s",filter_file);
				return 0;
			}
			
			DEBUG(200,"Opened file");
			//Get file length
			fseek(filter_file_fp, 0, SEEK_END);
			filter_file_len=ftell(filter_file_fp);
			fseek(filter_file_fp, 0, SEEK_SET);
			
			DEBUG(300,"File %s contains %i bytes", filter_file, filter_file_len);

			//Allocate memory
					*filter_buffer=(char *)calloc(1,(filter_file_len+1));
			if (!*filter_buffer)
			{
				WARN("Couldn't malloc buffer for file: %s", filter_file);
				return 0;
			}
			
			
			//Read file contents into buffer
			if (fread(*filter_buffer, filter_file_len, 1, filter_file_fp) != 1)
			{
				
				WARN("Couldn't read file: %s",filter_file);
				free(*filter_buffer);
				return 0;
			}
			
			fclose(filter_file_fp);
			
			//Null terminate
			(*filter_buffer)[filter_file_len] = '\0';
			
			
			return filter_file_len;
}




// Disable checksum feature of libnids 

void disable_chksum_ctl()
{
	static struct nids_chksum_ctl ctl;

	ctl.netaddr = inet_addr("0.0.0.0");
	ctl.mask = inet_addr("0.0.0.0");
	ctl.action = NIDS_DONT_CHKSUM;
	nids_register_chksum_ctl(&ctl, 1);
}


//function used to dump error counts

void print_errors()
{
    DEBUG(0,"VORTEX_ERRORS TOTAL: %u IP_SIZE: %u IP_FRAG: %u IP_HDR: %u IP_SRCRT: %u TCP_LIMIT: %u TCP_HDR: %u TCP_QUE: %u TCP_FLAGS: %u UDP_ALL: %u SCAN_ALL: %u VTX_RING: %u VTX_IO: %u VTX_MEM: %u OTHER: %u", errors.total, errors.ip_size, errors.ip_frag, errors.ip_hdr, errors.ip_srcrt, errors.tcp_limit, errors.tcp_hdr, errors.tcp_queue, errors.tcp_flags, errors.udp_all, errors.scan_all, errors.vtx_ring, errors.vtx_io, errors.vtx_mem, errors.other);
}

//Thread for periodically dumping error counts
//Since this thread only read, no synchronization is required
void *errors_thread(void *arg)
{
	//set priority of this thread--likely not portable
	if (setpriority(PRIO_PROCESS, gettid(), other_prio) != 0) 
  {
		WARN("Couldn't set error thread priority!");
  }
	//ok, now lock to a specific processor
	if (other_cpu >= 0)
	{
		cpu_set_t csmask;
  	    CPU_ZERO(&csmask);
  	    CPU_SET(other_cpu, &csmask);
  	    if (my_sched_setaffinity(gettid(), sizeof(cpu_set_t), &csmask) != 0) 
  	    {
  		    WARN("Couldn't set processor affinity for error thread");
		}
	}
	
	error_thread_init = 1;
	
		
	while ((error_interval > 0) && (program_state < 3))
	{
		print_errors();
		sleep(error_interval);
	} 
	pthread_exit(NULL);
}

//function that actually does the output of stats

void print_stats()
{
    struct pcap_stat pcap_dev_stats;
	pcap_dev_stats.ps_recv = 0;
	pcap_dev_stats.ps_drop = 0;
	
	
	if (nids_params.pcap_desc != NULL)
	{
 		if (pcap_stats(nids_params.pcap_desc, &pcap_dev_stats ) != 0)
 		{
 	        //didn't get anything back
 	        WARN("PCAP_STATS failed!");
 			pcap_dev_stats.ps_recv = 0;
 			pcap_dev_stats.ps_drop = 0;
 	    } else
 	    {
 	        //got something back, now increment long counter appropriately
 	        if (pcap_dev_stats.ps_recv < pcap_stats_last_recv)
 	        {
 	            //short counter rolled over
 	            pcap_stats_total_recv += (UINT_MAX - pcap_stats_last_recv) + pcap_dev_stats.ps_recv;
 	        } else
 	        {
 	            //simple case, simple increment
 	            pcap_stats_total_recv += (pcap_dev_stats.ps_recv - pcap_stats_last_recv); 
 	        }
 	        if (pcap_dev_stats.ps_drop < pcap_stats_last_drop)
 	        {
 	            //short counter rolled over
 	            pcap_stats_total_drop += (UINT_MAX - pcap_stats_last_drop) + pcap_dev_stats.ps_drop;
 	        } else
 	        {
 	            //simple case, simple increment
 	            pcap_stats_total_drop += (pcap_dev_stats.ps_drop - pcap_stats_last_drop);
 	        }
 	            
 	         //set "last" 32bit counters
            pcap_stats_last_recv = pcap_dev_stats.ps_recv;
            pcap_stats_last_drop = pcap_dev_stats.ps_drop;
 	
 	    }   
 	}
 	DEBUG(0,"VORTEX_STATS PCAP_RECV: %lu PCAP_DROP: %lu VTX_BYTES: %lu VTX_EST: %lu VTX_WAIT: %i VTX_CLOSE_TOT: %lu VTX_CLOSE: %lu VTX_LIMIT: %lu VTX_POLL: %lu VTX_TIMOUT: %lu VTX_IDLE: %lu VTX_RST: %lu VTX_EXIT: %lu VTX_BSF: %lu",pcap_stats_total_recv, pcap_stats_total_drop, collected_bytes, connection_id, ring_entries(), closed_connections, closed_connections_close, closed_connections_limit, closed_connections_poll, closed_connections_timeout, closed_connections_idle, closed_connections_reset, closed_connections_exit, closed_connections_bsf );
}

//Thread for periodically dumping stats
//since this thread only reads, no synchronization is required
void *stats_thread(void *arg)
{
	
	
	//set priority of this thread--likely not portable
	if (setpriority(PRIO_PROCESS, gettid(), other_prio) != 0) 
  {
		WARN("Couldn't set stats thread priority!");
  }
	
	//ok, now lock to a specific processor
	if (other_cpu >= 0)
	{
		cpu_set_t csmask;
  	    CPU_ZERO(&csmask);
  	    CPU_SET(other_cpu, &csmask);
  	    if (my_sched_setaffinity(gettid(), sizeof(cpu_set_t), &csmask) != 0) 
  	    {
  		    WARN("Couldn't set processor affinity for stats thread");
		}
	}
	stats_thread_init = 1;
	
	while ( (stats_interval > 0) &&  (program_state < 3) )
	{
		print_stats();
		sleep(stats_interval);
	} 
	pthread_exit(NULL);
}


//Free the malloc'd buffers associated with a connection
void free_connection(struct conn_param *a_conn)
{
	if (a_conn->to_server_data_p != NULL)
	{
		free(a_conn->to_server_data_p);
	}
	if (a_conn->to_client_data_p != NULL)
	{
		free(a_conn->to_client_data_p);
	}
	free(a_conn);
}

//Used to take all the connection data, provide it to consumers, free, and close
void dump_stream(struct conn_param *a_conn)
{
    //taken from linux/limits.h
  	char temp_filename[PATH_MAX];

    //these vars only used for debugging
    struct timeval system_time;
    char server_ip_string[INET6_ADDRSTRLEN+1];
    char client_ip_string[INET6_ADDRSTRLEN+1];
    //

    //these values used from timestomping
    struct timeval stomp_times[2];
    
    if (stomp_temp_file_timestamps)
    {
        stomp_times[0].tv_sec = last_timestamp;
        stomp_times[0].tv_usec = 0;
        stomp_times[1].tv_sec = last_timestamp;
        stomp_times[1].tv_usec = 0;    
    }

    DEBUG(400, "Closing Flow: %lu\n", a_conn->id);
				 
    //Output stream if we are collecting it and if there is data or we want to output empty streams
    if ((to_server_data_size_limit > 0) && ( (a_conn->to_server_data_p != NULL ) || ( output_empty_streams == 1 ) ) )
	{
	    DEBUG(400, "Dumping Server Data: %zu bytes", a_conn->to_server_data_size);
		data_filename(6, a_conn->id, a_conn->start, a_conn->last_activity, a_conn->close_state, a_conn->addr,VORTEX_DIRECTION_TO_SERVER, a_conn->to_server_data_size, a_conn->to_client_data_size, temp_filename);
		a_conn->to_server_data_fp = fopen(temp_filename, "w");
    	    	
    	if (a_conn->to_server_data_fp != NULL)
    	{
    		DEBUG(500, "Server data file opened: %s", temp_filename);
			
			//Only write data if there is data to write
			if (a_conn->to_server_data_p != NULL)
			{
			    if (fwrite(a_conn->to_server_data_p,a_conn->to_server_data_size, 1, a_conn->to_server_data_fp) == 1)
			    {
				    //write succesful;
				    DEBUG(500,"%zu bytes written to %s",a_conn->to_server_data_size,temp_filename);		
			    } else
			    {
				    //write failed
				    errors.vtx_io++;
    		        errors.total++;
				    WARN("Couldn't write %zu bytes to server data file: %s, skipping", a_conn->to_server_data_size, temp_filename);
      		    }
      		}
			fclose(a_conn->to_server_data_fp);

    	    if (stomp_temp_file_timestamps)
			{
			    //don't care about return. If we fail we're not going to do anything about it
			    utimes(temp_filename, stomp_times);
	        }
 			
		    //only print if creating file was succesful
		    //output filename to be read by consumer
		    printf("%s\n",temp_filename);
		
		} else
		{
    		    errors.vtx_io++;
    		    errors.total++;
      	        ERROR("Couldn't open server data file: %s, skipping",temp_filename);
        }
		
		
			
    }
	
	if ((to_client_data_size_limit > 0) && ( (a_conn->to_client_data_p != NULL ) || ( output_empty_streams == 1 ) ) )
	{
		DEBUG(400, "Dumping Client Data: %zu bytes", a_conn->to_client_data_size);
		data_filename(6, a_conn->id, a_conn->start, a_conn->last_activity, a_conn->close_state, a_conn->addr,VORTEX_DIRECTION_TO_CLIENT, a_conn->to_server_data_size, a_conn->to_client_data_size, temp_filename);
		a_conn->to_client_data_fp = fopen(temp_filename, "w");
    	
    	if (a_conn->to_client_data_fp != NULL)
    	{
    		DEBUG(500, "Client data file opened: %s", temp_filename);
			
			//Only write data if there is data to write
			if (a_conn->to_client_data_p != NULL)
			{
    		    if (fwrite(a_conn->to_client_data_p,a_conn->to_client_data_size, 1, a_conn->to_client_data_fp) == 1)
				{
					//write succesful;
					DEBUG(500,"%zu bytes written to %s",a_conn->to_server_data_size,temp_filename);		
				} else
				{
					//write failed
					errors.vtx_io++;
    		        errors.total++;
					WARN("Couldn't write %zu bytes to client data file: %s, skipping", a_conn->to_client_data_size, temp_filename);
				}
			}	
			fclose(a_conn->to_client_data_fp);
    	    
    	    if (stomp_temp_file_timestamps)
			{
			    //don't care about return. If we fail we're not going to do anything about it
			    utimes(temp_filename, stomp_times);
			}
   
    	    //only print if creating file was succesful
    	    //output filename to be read by consumer
		    printf("%s\n",temp_filename);
    	
    	} else
		{
    		errors.vtx_io++;
    		errors.total++;
      	    ERROR("Couldn't open client data file: %s, skipping",temp_filename);
        }
		
			
	}
	
	//do debuging for streams
    if (debug_level >= 112)
    {
        //get the server and client ips
        inet_ntop(AF_INET, (const void *)&a_conn->addr.saddr, client_ip_string, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET, (const void *)&a_conn->addr.daddr, server_ip_string, INET6_ADDRSTRLEN);
        
        gettimeofday(&system_time, NULL);
        //don't do pacp time because may not be safe in this thread
        DEBUG(112, "Wrote connection: %lu, conn: %s:%i-%s:%i, system time: %lu.%06lu, pcap_time: 0.0", a_conn->id, client_ip_string, a_conn->addr.source, server_ip_string, a_conn->addr.dest, system_time.tv_sec, system_time.tv_usec);
    }
	
	free_connection(a_conn);
}


//Thread for writing stream data
void *conn_writer(void *arg)
{
	//set priority of this thread--likely not portable
	if (setpriority(PRIO_PROCESS, gettid(), other_prio) != 0) 
  {
		WARN("Couldn't set output thread priority!");
  }
  
  //ok, now lock to a specific processor
	if (other_cpu >= 0)
	{
		cpu_set_t csmask;
  	    CPU_ZERO(&csmask);
  	    CPU_SET(other_cpu, &csmask);
  	    if (my_sched_setaffinity(gettid(), sizeof(cpu_set_t), &csmask) != 0) 
  	    {
  		    WARN("Couldn't set processor affinity for output thread");
		}
  }
  output_thread_init = 1;
  
	while(program_state < 3)
	{
		usleep(conn_ring_poll_interval);
		while(!(ring_empty()))
		{
			dump_stream(ring_remove());
		}
		if ((program_state == 2) && (ring_empty()))
		{
			//give ourselves time to ensure all connections have been put into ring
			//since there is (intentionally) no synchronization between capture thread and output thread, this is probably the best we can do.
			usleep(conn_ring_poll_interval*2);
			if (ring_empty())
			{
				program_state = 3;
			}
		}
	}
	pthread_exit(NULL);
}

void close_connection(struct conn_param *a_conn, char close_reason)
{   
		
		//these vars only used for debugging
        struct timeval system_time;
        char server_ip_string[INET6_ADDRSTRLEN+1];
        char client_ip_string[INET6_ADDRSTRLEN+1];
        //
		
		//pthread_t thread_h;
  	    //int pthread_rc;
		
		//thread safety!!! we only reach this check in a single thread. If we ever get here in multiple threads, we need a mutex.
		//							This check prevents the connection from being closed more than once
		if (a_conn->close_state >= NIDS_CLOSE)
		{
			return;
		}
		
		
        //do debuging for new streams
        if (debug_level >= 110)
        {
            //get the server and client ips
            inet_ntop(AF_INET, (const void *)&a_conn->addr.saddr, client_ip_string, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET, (const void *)&a_conn->addr.daddr, server_ip_string, INET6_ADDRSTRLEN);
            
            gettimeofday(&system_time, NULL);
            DEBUG(110, "End connection: %lu, conn: %s:%i-%s:%i, system time: %lu.%06lu, pcap_time: %lu.%06lu", a_conn->id, client_ip_string, a_conn->addr.source, server_ip_string, a_conn->addr.dest, system_time.tv_sec, system_time.tv_usec, nids_last_pcap_header->ts.tv_sec, nids_last_pcap_header->ts.tv_usec);
        }
		
		a_conn->close_state = close_reason;
		rem_conn_tcp(a_conn);
		
				
		//block here if we are reading from pcap, no reason to drop packets.....
		if (nids_params.filename != NULL)
		{
			while(ring_full())
			{
				usleep(conn_ring_poll_interval);
			}
		}
		
		//if there is room in ring, close connection normally. If not, close it brutually doing the frees.
		if (ring_full())
		{
			free_connection(a_conn);
			errors.vtx_ring++;
    	errors.total++;
		} else
		{
			ring_add(a_conn);
		} 
		
		
		closed_connections++;
    
    switch (close_reason)
    {
    	
    	case NIDS_CLOSE:
    		closed_connections_close++;
    	break;
    	case NIDS_RESET:
    		closed_connections_reset++;
    	break;
    	case NIDS_TIMED_OUT:
    		closed_connections_timeout++;
    	break;
    	case NIDS_EXITING:
    		closed_connections_exit++;
    	break;
    	case VORTEX_SIZE_LIMIT_REACHED:
    		closed_connections_limit++;
    	break;
    	case VORTEX_IDLE:
    		closed_connections_idle++;
    	break;
    	
    }
    
    
    
    if ((max_connections > 0) && (closed_connections >= max_connections))
    {
    	WARN("Reached max connections, exiting...")
    	program_state = 2;
    	//nids_exit();
    	//wait_for_other_threads();
    	//TODO: make this ending a little less abrupt
    	
    	    	
    	DIE("Stopping after %lu connections", max_connections)		
    }
}


int filter_stream_bsf(struct tcp_stream *a_tcp)
{

#ifdef WITH_BSF
	if (bsf_filter(bsf_desc, a_tcp->addr.saddr, a_tcp->addr.source, a_tcp->addr.daddr, a_tcp->addr.dest) == BSF_RESULT_PASS)
	{
		return 1;
	} else
	{
		return 0;
	}
#else
	return 1;
#endif
}


void tcp_callback (struct tcp_stream *a_tcp, struct conn_param **conn_param_ptr)
{
  
    
  //these vars only used for debugging
  struct timeval system_time;
  char server_ip_string[INET6_ADDRSTRLEN+1];
  char client_ip_string[INET6_ADDRSTRLEN+1];
  //  
  
  struct conn_param *a_conn;
  
  char *realloc_old_ptr = NULL;
  size_t realloc_old_size = 0;
  
  
  if (debug_level >= 150)
  {
    gettimeofday(&system_time, NULL);
    if (a_tcp->nids_state == NIDS_JUST_EST)
    {
        DEBUG(150, "TCP callback. %s, state: %i, system time: %lu.%06lu, pcap_time: %lu.%06lu", "na", a_tcp->nids_state, system_time.tv_sec, system_time.tv_usec, nids_last_pcap_header->ts.tv_sec, nids_last_pcap_header->ts.tv_usec);
    } else if (a_tcp->nids_state == NIDS_DATA)
    {
        DEBUG(151, "TCP callback: %lu, state: %i, system time: %lu.%06lu, pcap_time: %lu.%06lu", ((struct conn_param *) *conn_param_ptr)->id, a_tcp->nids_state, system_time.tv_sec, system_time.tv_usec, nids_last_pcap_header->ts.tv_sec, nids_last_pcap_header->ts.tv_usec);
    } else
    {
        DEBUG(150, "TCP callback: %lu, state: %i, system time: %lu.%06lu, pcap_time: %lu.%06lu", ((struct conn_param *) *conn_param_ptr)->id, a_tcp->nids_state, system_time.tv_sec, system_time.tv_usec, nids_last_pcap_header->ts.tv_sec, nids_last_pcap_header->ts.tv_usec);
    }
  }
  
  
  //short circuit if we are done
  if (program_state > 1)
  {
  	nids_exit();
  	return;
  }
  
  
  if (a_tcp->nids_state != NIDS_EXITING)
  {
  	last_timestamp = (unsigned int) nids_last_pcap_header->ts.tv_sec;
  }
  
  //check for idle connections now
  //we are intentionally only doing one per callback
  if ((tcp_max_idle >= 0) && (tcp_head != NULL))
  {
  	//Make sure we don't clobber current connection
  	if (a_tcp != tcp_head->nids_stream)
  	{
  		if ((last_timestamp - tcp_head->last_activity) > tcp_max_idle)
  		{
  			nids_free_tcp_stream(tcp_head->nids_stream);
  			close_connection(tcp_head, VORTEX_IDLE);		
  		}
  	}
  }
  
  
  
  if (a_tcp->nids_state == NIDS_JUST_EST)
  {
    
  	connection_id++;
    
    //do debuging for new streams
    if (debug_level >= 111)
    {
        //get the server and client ips
        inet_ntop(AF_INET, (const void *)&a_tcp->addr.saddr, client_ip_string, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET, (const void *)&a_tcp->addr.daddr, server_ip_string, INET6_ADDRSTRLEN);
        
        gettimeofday(&system_time, NULL);
        DEBUG(111, "New connection: %lu, conn: %s:%i-%s:%i, system time: %lu.%06lu, pcap_time: %lu.%06lu", connection_id, client_ip_string, a_tcp->addr.source, server_ip_string, a_tcp->addr.dest, system_time.tv_sec, system_time.tv_usec, nids_last_pcap_header->ts.tv_sec, nids_last_pcap_header->ts.tv_usec);
    }
    
    
    //Filtering First
    
    if (bsf_enabled)
    {
    	if (filter_stream_bsf(a_tcp))
    	{
    		DEBUG(450,"Stream PASSED BSF");
    	
    	} else
    	{
    		DEBUG(450,"Stream FAILED BSF");
    		closed_connections_bsf++;
    		closed_connections++;
    		return;
    	}
    }
    
    
    //Polling
    if (connection_id % poll_rate == 0)
    {	
    	DEBUG(400,"Setting up new connection with id: %lu",connection_id);
    	
    	//Set up conn_param struct
    	a_conn=calloc(1,sizeof(struct conn_param));
    	  
    	if (a_conn == NULL)
    	{
    	    inet_ntop(AF_INET, (const void *)&a_tcp->addr.saddr, client_ip_string, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET, (const void *)&a_tcp->addr.daddr, server_ip_string, INET6_ADDRSTRLEN);
    	    
    	    //return without setting up connection param and tell libNIDS to ignore this one--this should happen very infrequently
    	    ERROR("Couldn't malloc connection parameter struct, skipping connection: conn: %s:%i-%s:%i\n", client_ip_string, a_tcp->addr.source, server_ip_string, a_tcp->addr.dest);
    	        	       	    
    	    //re-use conn id
    	    connection_id--;
    	    nids_free_tcp_stream(a_tcp);
    	    errors.vtx_mem++;
    	    errors.total++;
    	    return;
    	}
    	
    	
    	
    	if ((collection == VORTEX_DIRECTION_TO_SERVER) || (collection == VORTEX_DIRECTION_TO_BOTH))
    	{
    		a_tcp->server.collect++; // we want data received by client (to server)
    	}
    	if ((collection == VORTEX_DIRECTION_TO_CLIENT) || (collection == VORTEX_DIRECTION_TO_BOTH))
    	{
    		a_tcp->client.collect++; // we want data received by server (to client)
		}
    	
  		
    	  
    	*conn_param_ptr=a_conn;
			
			//set id information	
			a_conn->id=connection_id;
			memcpy (&a_conn->addr, &a_tcp->addr, sizeof(struct tuple4));
			
			a_conn->nids_stream = a_tcp;
			//add to timeout list
			add_conn_tcp(a_conn);
							
			//DEBUG(400, "Flow %d Established: %s\n", a_conn->id, connection_string);
			
			//Set the data sizes to 0 (collecting or not)
			a_conn->to_server_data_size = 0;
			a_conn->to_server_data_size_exceeded = 0;
			a_conn->to_client_data_size = 0;         
			a_conn->to_client_data_size_exceeded = 0;   
			//set the data pointers to null (collecting or not)
			a_conn->to_server_data_p = NULL;
			a_conn->to_client_data_p = NULL;
			a_conn->close_state = 0;
			//TODO: change this to time
			a_conn->start = last_timestamp;
			a_conn->last_activity = last_timestamp;
			
			//
		    a_conn->to_server_buffer_size = 0;
		    a_conn->to_client_buffer_size = 0;
		
		} else 
    {
    	//This is not a polled connection, close it!
    	closed_connections_poll++;
    	closed_connections++;
  	} //end of polling conditional
    return;
	}//End of NIDS_JUST_EST
  else
  {
  	//Not Just Established
    //Get our conn_param struct
    a_conn = *conn_param_ptr;
  	//return if we don't have a conn_param for this connection (probably exluded due to polling)
  	if (a_conn == NULL)
  	{
  		return;		
  	}
  }
    
  //CLOSE, RESET, TIMED_OUT, EXITING
  if ( (a_tcp->nids_state == NIDS_CLOSE) || (a_tcp->nids_state == NIDS_RESET) || (a_tcp->nids_state == NIDS_TIMED_OUT) || (a_tcp->nids_state == NIDS_EXITING) )
  {
  
    
    //fprintf (stderr, "Connection %d Closed\n", a_conn->id);
        
    close_connection(a_conn, a_tcp->nids_state);

		return;
  }
  
  if (a_tcp->nids_state == NIDS_DATA)
  {
  	a_conn->last_activity = last_timestamp;
  	bump_conn_tcp(a_conn);
  	if ((a_tcp->client.count_new) && ((collection == VORTEX_DIRECTION_TO_CLIENT) || (collection == VORTEX_DIRECTION_TO_BOTH))) //probably ought to check if we are colleting also
	{
    	
    	//see if buffer needs to be realloc'd
    	if ( a_tcp->client.count_new+a_conn->to_client_data_size > a_conn->to_client_buffer_size )
    	{
    	    realloc_old_ptr = a_conn->to_client_data_p;
    	    realloc_old_size = a_conn->to_client_buffer_size;
    	    if (realloc_increase_percent == 0 )
    	    {
    	        a_conn->to_client_buffer_size = a_conn->to_client_data_size + a_tcp->client.count_new;
    	    }
    	    if ( a_conn->to_client_buffer_size == 0 )
    	    {
    	        a_conn->to_client_buffer_size = base_realloc_size;
    	    }        
    	    while ( a_tcp->client.count_new+a_conn->to_client_data_size > a_conn->to_client_buffer_size )
    	    {
    	        if ( a_conn->to_client_buffer_size >= realloc_increase_threshold )
    	        {    
    	            a_conn->to_client_buffer_size = SIZE_MAX;
    	        } else
    	        {
    	            a_conn->to_client_buffer_size *= realloc_increase_factor;
    	        }
    	    }
    	    a_conn->to_client_data_p = realloc(a_conn->to_client_data_p,a_conn->to_client_buffer_size);
    	    
    	    //not used
    	    //if (realloc_old_ptr != a_conn->to_client_data_p)
	        //{
	        //    realloc_copy_count++;
	        //    realloc_copy_bytes += a_conn->to_client_data_size;    
	        //}
	    }    
    	
    	  
        //copy client data to connection buffer
		if (a_conn->to_client_data_p == NULL)
    	{
    	    errors.vtx_mem++;
    	    errors.total++;
    	    ERROR("Couldn't realloc client data buffer (leaving hole in data) in conn: %lu\n", a_conn->id);
    	    a_conn->to_client_data_p = realloc_old_ptr;
    	    a_conn->to_client_buffer_size = realloc_old_size;
    	    //this stream has a "hole" in it due to realloc failure but currently is not marked as such in any way--these errors should be very rare
      	} else
    	{
	        //Copy the data and set the size accordingly
	    	memcpy((a_conn->to_client_data_p + a_conn->to_client_data_size), a_tcp->client.data, a_tcp->client.count_new);
    		a_conn->to_client_data_size = a_tcp->client.count_new + a_conn->to_client_data_size;
    	    collected_bytes += (unsigned long int)a_tcp->client.count_new;
    	}		
	
	
	
        //check if connection collection size has been exceeded
		if (a_conn->to_client_data_size >= to_client_data_size_limit )
	    {
	    	a_conn->to_client_data_size_exceeded += (a_conn->to_client_data_size - to_client_data_size_limit);
	    	DEBUG(500, "Client max collection size exceeded for connection %lu by %d bytes\n", a_conn->id, a_conn->to_client_data_size_exceeded );
      	    //disable further data collection
      	    a_tcp->client.collect--;
      
      	    //close this connection if we have exceeded () client and server limits (libnids still tracks it, but we don't)
       	    if ((a_conn->to_client_data_size >= to_client_data_size_limit) &&  (a_conn->to_server_data_size >= to_server_data_size_limit ))
      	    {
      		    DEBUG(500,"Closing Connection %lu becuase size limits reached", a_conn->id)
      		    close_connection(a_conn, VORTEX_SIZE_LIMIT_REACHED);
      	    }
      
        } 
	}
    if ((a_tcp->server.count_new) && ((collection == VORTEX_DIRECTION_TO_SERVER) || (collection == VORTEX_DIRECTION_TO_BOTH)))
	{
	    
        //see if buffer needs to be realloc'd
    	if ( a_tcp->server.count_new+a_conn->to_server_data_size > a_conn->to_server_buffer_size )
    	{
    	    realloc_old_ptr = a_conn->to_server_data_p;
    	    realloc_old_size = a_conn->to_server_buffer_size;
    	    if (realloc_increase_percent == 0 )
    	    {
    	        a_conn->to_server_buffer_size = a_conn->to_server_data_size + a_tcp->server.count_new;
    	    }
    	    if ( a_conn->to_server_buffer_size == 0 )
    	    {
    	        a_conn->to_server_buffer_size = base_realloc_size;
    	    }    
    	    while ( a_tcp->server.count_new+a_conn->to_server_data_size > a_conn->to_server_buffer_size )
    	    {
    	        if ( a_conn->to_server_buffer_size >= realloc_increase_threshold )
    	        {    
    	            a_conn->to_server_buffer_size = SIZE_MAX;
    	        } else
    	        {
    	            a_conn->to_server_buffer_size *= realloc_increase_factor;
    	        }
    	    }
    	    a_conn->to_server_data_p = realloc(a_conn->to_server_data_p,a_conn->to_server_buffer_size);
    	    
    	    //not used
    	    //if (realloc_old_ptr != a_conn->to_server_data_p)
	        //{
	        //    realloc_copy_count++;
	        //    realloc_copy_bytes += a_conn->to_server_data_size;    
	        //}
	    }    
    	
    	  
        //copy server data to connection buffer
		if (a_conn->to_server_data_p == NULL)
    	{
    	    errors.vtx_mem++;
    	    errors.total++;
    	    ERROR("Couldn't realloc server data buffer (leaving hole in data) in conn: %lu\n", a_conn->id);
    	    a_conn->to_server_data_p = realloc_old_ptr;
    	    a_conn->to_server_buffer_size = realloc_old_size;
    	    //this stream has a "hole" in it due to realloc failure but currently is not marked as such in any way--these errors should be very rare
      	} else
    	{
	        //Copy the data and set the size accordingly
	    	memcpy((a_conn->to_server_data_p + a_conn->to_server_data_size), a_tcp->server.data, a_tcp->server.count_new);
    		a_conn->to_server_data_size = a_tcp->server.count_new + a_conn->to_server_data_size;
    	    collected_bytes += (unsigned long int)a_tcp->server.count_new;
    	}	  
	  		    
	    //check if connection collection size has been exceeded
	    if (a_conn->to_server_data_size >= to_server_data_size_limit )
	    {
	    	a_conn->to_server_data_size_exceeded += (a_conn->to_server_data_size - to_server_data_size_limit);
	    	DEBUG(500, "Server max collection size exceeded for connection %lu by %d bytes\n", a_conn->id, a_conn->to_server_data_size_exceeded );
	    	//disable further data collection
      	    a_tcp->server.collect--;
      	
      	    //close this connection if we have exceeded () client and server limits (libnids still tracks it, but we don't)
       	    if ((a_conn->to_client_data_size >= to_client_data_size_limit) &&  (a_conn->to_server_data_size >= to_server_data_size_limit ))
      	    {
      		    DEBUG(500,"Closing Connection %lu becuase size limits reached", a_conn->id)
      		    close_connection(a_conn, VORTEX_SIZE_LIMIT_REACHED);
      	    }
      	
	    }
	      
	}
 
  return;    
  }//end of NIDS_DATA
  
  //Should never get here
  DIE("Reached Unreachable State\n");
  
  return;

}//End of tcp_callback

int main (int argc, char **argv)
{
	int opt;
	process_name = argv[0];
	pthread_t stats_thread_h;
  pthread_t error_thread_h;
  pthread_t writer_thread_h;
  int pthread_rc;
	errors.total = 0;
	errors.ip_size = 0;
	errors.ip_frag = 0;
	errors.ip_hdr = 0;
	errors.ip_srcrt = 0;
	errors.tcp_limit = 0;
	errors.tcp_hdr = 0;
	errors.tcp_queue = 0;
	errors.tcp_flags = 0;
	errors.udp_all = 0;
	errors.scan_all = 0;
	errors.vtx_ring = 0;
	errors.vtx_io = 0;
	errors.vtx_mem = 0;
	errors.other = 0;
	
	
	logging_name = "Vortex";
	
	DEBUG(50, "Starting up Vortex");
	
  //Set pthread attributes (default to detached)  
  //pthread_attr_init(&pthread_attrs);
  //pthread_attr_setdetachstate(&pthread_attrs, PTHREAD_CREATE_DETACHED);
  
  nids_params.n_tcp_streams = 1048576;
  nids_params.n_hosts = 65536;
  
    
  //parse command line options
  DEBUG(100, "Parsing Commnad Line Options");
  
  //set some defaults
   
  while ((opt = getopt(argc, argv, "hc:f:F:g:G:i:lpr:u:S:C:t:s:H:mwkq:D:M:P:T:E:L:Q:R:n:N:o:O:eK:vx:d")) != -1)
	{
		switch (opt) 
		{
		case 'c':
			max_connections = atoi(optarg);
			DEBUG(100,"Max connections set to %lu",max_connections);
			break;
  	
  	case 'f':
			filter_string = optarg;
			DEBUG(100,"Using packet filter from CLI arg: %s",filter_string);
			break;
  	
  	case 'F':
			filter_file = optarg;
			DEBUG(100,"Using packet filter from file: %s",filter_file);
			break;
  	
  	case 'g':
#ifdef WITH_BSF
			bsf_filter_string = optarg;
			bsf_enabled = 1;
			DEBUG(100,"Using arg filter from CLI arg: %s",bsf_filter_string);
#else
			DIE("Not compiled with support for BSF. Recompile with support for BSF (-DWITH_BSF).");
#endif
			break;
  	
  	case 'G':
#ifdef WITH_BSF
			bsf_filter_file = optarg;
			bsf_enabled = 1;
			DEBUG(100,"Using stream filter from file: %s",bsf_filter_file);
#else
			DIE("Not compiled with support for BSF. Recompile with support for BSF (-DWITH_BSF).");
#endif
			break;
  	
  	case 'i':
			nids_params.device = optarg;
			DEBUG(100,"Using device: %s",nids_params.device);
			break;
  	
  	case 'l':
			//set STDOUT to line buffering
			#ifdef HAVE_SETLINEBUF
				setlinebuf(stdout);
			#else
				setvbuf(stdout, NULL, _IOLBF, 0);
			#endif
			DEBUG(100,"Ouput set to line buffering");
			break;
			
		case 'p':
			//Don't put capture in promisc mode
			nids_params.promisc = 0;
			DEBUG(100,"Promisc mode disabled");
			break;
  	
  	case 'r':
			nids_params.filename = optarg;
			DEBUG(100,"Reading from capture file: %s",nids_params.filename);
			break;
		
		case 'u':
			user = optarg;
			DEBUG(100,"Switching to user: %s",user);
			break;
		
		case 'S':
			to_server_data_size_limit = (size_t)atoll(optarg);
			if (to_server_data_size_limit > SIZE_MAX)
			{
			    DIE("Invalid to server size limit of %llu, must be under %llu", (unsigned long long)to_server_data_size_limit, (unsigned long long)SIZE_MAX);    
			}
			DEBUG(100,"Size limit of data to server: %llu", (unsigned long long)to_server_data_size_limit);
			break;
		
		case 'C':
			to_client_data_size_limit = (size_t)atoll(optarg);
			if (to_client_data_size_limit > SIZE_MAX)
			{
			    DIE("Invalid to client size limit of %llu, must be under %llu", (unsigned long long)to_server_data_size_limit, (unsigned long long)SIZE_MAX);    
			}
			DEBUG(100,"Size limit of data to client: %llu", (unsigned long long)to_server_data_size_limit);
			break;
		
		case 't':
			temp_data_dir = optarg;
			DEBUG(100,"Using temp dir: %s",temp_data_dir);
			break;
		
		case 's':
			//size of TCP streams hash tables (number of TCP streams to follow is 3/4 of this value)
			nids_params.n_tcp_streams = atoi(optarg);
			DEBUG(100,"Set nids parameter n_tcp_streams: %i",nids_params.n_tcp_streams);
			break;
		
		case 'H':
			//number of hosts to track for IP defrag
			nids_params.n_hosts = atoi(optarg);
			DEBUG(100,"Set nids parameter n_hosts: %i",nids_params.n_hosts);
			break;
  	
  	case 'm':
			//Set libnids to multiproc mode
			nids_params.multiproc = 1;
			DEBUG(100,"Enable NIDS multiproc mode");
			break;
  	
  	case 'q':
			//Set libnids queuelimit
			nids_params.queue_limit = atoi(optarg);
			DEBUG(100,"Set nids parameter queue_limit: %i",nids_params.queue_limit);
			break;
  	
  	case 'D':
			debug_level = atoi(optarg);
			DEBUG(100,"Set debug level to %i",debug_level);
			break;

  	case 'M':
  		snap_len = atoi(optarg);
			DEBUG(100,"Using snap len: %i",snap_len);
			break;

	case 'w':
			//Set libnids to enable TCP/IP workaround for non-RFC compliant stacks 
			DEBUG(100,"Enabled TCP workarounds");
			nids_params.tcp_workarounds = 1;
			break;
			
	case 'k':
			//Set libnids to enable TCP/IP workaround for non-RFC compliant stacks 
		  disable_chksum_ctl();
      DEBUG(100,"Disable TCP checksum checking");
      break;
	case 'P':
			poll_rate = atoi(optarg);
			DEBUG(100,"Polling connections at rate: %i",poll_rate);
			break;
	case 'T':
			stats_interval = atoi(optarg);
			DEBUG(100,"Reporting stats at rate: %u",stats_interval);
			break;
	case 'E':
			error_interval = atoi(optarg);
			DEBUG(100,"Reporting error at rate: %u",error_interval);
			break;		
  case 'L':
			logging_name = optarg;
			DEBUG(100,"Using logging name of: %s",logging_name);
			break;
  
  case 'Q':
			if (atoi(optarg) > 1)
			{
				conn_ring_size = atoi(optarg);
			}
			DEBUG(100,"Using out queue size of: %i",conn_ring_size);
			break;		
			
	case 'R':
			if (atoi(optarg) > 1)
			{
				conn_ring_poll_interval = atoi(optarg);
			}
			DEBUG(100,"Stream output thread using interval of: %i usecs",conn_ring_poll_interval);
			break;		
  
  case 'n':
			capture_prio = atoi(optarg);
			DEBUG(100,"Set capture thread priority to: %i",capture_prio);
			break;
  
  case 'N':
			other_prio = atoi(optarg);
			DEBUG(100,"Set other thread priority to: %i",other_prio);
			break;
  
  case 'o':
			capture_cpu = atoi(optarg);
			DEBUG(100,"Set capture thread cpu affinity to: %i",capture_cpu);
			break;
  
  case 'O':
			other_cpu = atoi(optarg);
			DEBUG(100,"Set other thread cpu affinity to: %i",other_cpu);
			break;
  case 'e':
  	extended_output = 1;
  	DEBUG(100,"Enabling extended output");
  	break;
  
  case 'K':
		tcp_max_idle = atoi(optarg);
		DEBUG(100,"Max TCP IDLE time to: %i",tcp_max_idle);
		break;
  case 'v':
  	output_empty_streams = 1;
  	DEBUG(100,"Enabling output of empty streams");
  	break;
  
  case 'x':
	realloc_increase_percent = atoi(optarg);
	if ((realloc_increase_percent < 0) || (realloc_increase_percent > REALLOC_INCREASE_PERCENT_MAX))
	{
	    DIE("Invalid value for stream data buffer increase percent. Must be between 0 and %i", REALLOC_INCREASE_PERCENT_MAX);
	}
	
	DEBUG(100,"Stream data buffer increase set to: %i%%",realloc_increase_percent);
	break;
  case 'd':
  	disable_temp_file_stomp = 1;
  	DEBUG(100,"Disabling modifcation of output file timestamp");
  	break;
  
  case 'h':
  	print_usage();
  	exit(0);
  	break;
  
   	default:
  		print_usage();
  		DIE("Invalid option %c", opt);
  		break;
  	
  	}
  }
  
  
  //open syslog connection
	openlog(logging_name, 0, LOG_LOCAL0);
  
  //get libnids syslog function before we override it.
  libnids_syslog=nids_params.syslog;
  nids_params.syslog=vortex_nids_syslog;
  
  //make sure path isn't so long we'll overrun the filename buffers
  //The 2 is for the null char and for / that will need to separate dir from metadata
  if (strnlen(temp_data_dir, PATH_MAX) > ((unsigned int)(PATH_MAX - (METADATA_MAX + 2))))
  {
  	DIE("Specified path of temp directory is too long. The temp directory must be less than %u chars in length", (unsigned int)(PATH_MAX - (METADATA_MAX + 2)));
  }
    
  //too many args
  if (argc > (optind))
  {
  	print_usage();
  	DIE("Invalid command line options!\nYou must quote the filter expression");
  }
  
  //packet filter, if any is supplied
  if ((filter_file != NULL) || (filter_string != NULL))
  {
  	if ((filter_file != NULL) && (filter_string != NULL))
  	{
  		DIE("Can't specify packet filter in CLI arg and file at same time!");
  	}
  	
  	if (filter_file != NULL)
  	{
  	
  		//Load filter from file
  		
  		if (read_file_into_buffer(filter_file, &filter_string) == 0)
  		{
  			DIE("Couldn't Read Filter File %s", filter_file);	
  		} 
  		
  	}
  	
  	nids_params.pcap_filter = filter_string;
  	DEBUG(300, "Using packet filter: %s", filter_string);
  	
  }
  

#ifdef WITH_BSF  
  //now deal with bsf style filter
  if (bsf_enabled)
  {
  	//make sure we aren't using filter from CLI arg and from file at same time 
  	if ((bsf_filter_file != NULL) && (bsf_filter_string != NULL))
  	{
  		DIE("Can't specify stream filter in CLI arg and file at same time!");
  	}
  	
  	//make sure filter expression is in bsf_filter_string;
  	if (bsf_filter_string == NULL)
  	{
  		//load filter string from file
  		if (read_file_into_buffer(bsf_filter_file, &bsf_filter_string) == 0)
  		{
  			DIE("Couldn't Read Stream Filter File %s", bsf_filter_file);	
  		}
  	}
  	
  	
  	bsf_desc = bsf_create();
		if (bsf_desc == NULL)
		{
			printf("Couldn't create BSF!\n");		
			exit(1);
		}
  	if (bsf_compile(bsf_desc, bsf_filter_string, 0) == BSF_ERROR_NONE)
  	{
  		DEBUG(300,"BSF compiled successfully: %s", bsf_filter_string);
  	} else
  	{
  		DIE("BSF compilation failed, please check syntax: %s", bsf_filter_string);
  	}
  }
#endif
    
  //Set collection direction
  if ((to_server_data_size_limit == 0) && (to_client_data_size_limit == 0))
  {
  	DIE("Nothing to do: Both server and client collection limit set to 0B");
  }
  if ((to_server_data_size_limit > 0) && (to_client_data_size_limit > 0))
  {
  	collection = VORTEX_DIRECTION_TO_BOTH;
  }
  if ((to_server_data_size_limit > 0) && (to_client_data_size_limit == 0))
  {
  	collection = VORTEX_DIRECTION_TO_SERVER;
  }
  if ((to_server_data_size_limit == 0) && (to_client_data_size_limit > 0))
  {
  	collection = VORTEX_DIRECTION_TO_CLIENT;
  }
  
  
  //TODO:
  //check that temp dir exists
  
  //die if capture device and filename are set
  if ((nids_params.device != NULL) && (nids_params.filename != NULL))
  {
  	DIE("Can't specifiy both a capture device and a capture file!");		
  }
  
  //set file stomping if appropriate
  if ((nids_params.filename != NULL) && ( disable_temp_file_stomp == 0 ))
  {
    stomp_temp_file_timestamps = 1;
  }
  
  //set stuff for realloc growth
  realloc_increase_factor = ((float)(100 + realloc_increase_percent))/100;
  DEBUG(100,"Stream data buffer growth factor set to: %f",realloc_increase_factor);
  realloc_increase_threshold = (int)(SIZE_MAX/realloc_increase_factor) - 1;
    
  //Open our own pcap descriptor so we can set the snap length
  if (nids_params.device != NULL)
  {
  	pcap_err_buf[0] = '\0';
  	
  	  	
  	desc = pcap_open_live(nids_params.device, snap_len, nids_params.promisc, nids_params.pcap_timeout, pcap_err_buf);
  	if (desc == NULL)
  	{
  		DIE("Couldn't open device (%s) for packet capture: %s",nids_params.device,pcap_err_buf);		
  	} else
  	{
  		DEBUG(20,"Opened device (%s) for packet capture: %s",nids_params.device,pcap_err_buf);
  		nids_params.pcap_desc = desc;
  	}
  }
  
  
  if (poll_rate < 1)
  {
  	DIE("Poll rate must be greater than or equal to 1");		
  }
  
  //set up ring buffer and start stream writer thread
  //first malloc buffer
  conn_ring = (struct conn_param **) malloc(conn_ring_size * sizeof(struct conn_param *));
  if (conn_ring == NULL)
  {
  	DIE("Couldn't intialize connection ring of size: %i", conn_ring_size);
  }
  //start stream writer thread
  if( (pthread_rc = pthread_create(&writer_thread_h, NULL, conn_writer, NULL)) )
  {
    		DIE("Error starting stream writer thread. return code from pthread_create() is %d\n", pthread_rc);
  }
  
    
  //start stats threads
  if (stats_interval > 0)
  {
  	if( (pthread_rc = pthread_create(&stats_thread_h, NULL, stats_thread, NULL)) )
  	{
    	WARN("Error Creating stats reporting thread. Stats will not be reported. return code from pthread_create() is %d\n", pthread_rc);
  		stats_interval = 0;
  	}
  }
    
  //start errors thread
  if (error_interval > 0)
  {
  	if( (pthread_rc = pthread_create(&error_thread_h, NULL, errors_thread, NULL)) )
  	{
    	WARN("Error Creating error reporting thread. Error counts will not be periodically reported. return code from pthread_create() is %d\n", pthread_rc);
  		error_interval = 0;
  	}
  }
  
  
  
  //set priority for capture thread before we drop priveledges
  //This is most likely not portable......
  if (setpriority(PRIO_PROCESS, gettid(), capture_prio) != 0) 
  {
		WARN("Couldn't set capture thread priority!");
  }
	//ok, now lock to a specific processor
	
	if (capture_cpu >= 0)
	{
		cpu_set_t csmask;
  	    CPU_ZERO(&csmask);
  	    CPU_SET(capture_cpu, &csmask);
  	    if (my_sched_setaffinity(gettid(), sizeof(cpu_set_t), &csmask) != 0) 
  	    {
  		    WARN("Couldn't set processor affinity for capture thread");
		}
	}
  //Disable Port Scan Detection
  nids_params.scan_num_hosts=0;

   	
 	DEBUG(100,"Using LIBNIDS version %i.%i\n",NIDS_MAJOR,NIDS_MINOR);
  
  if (!nids_init ())
  {
  	DIE("libNIDS init failed: %s",nids_errbuf);
  }
  
  
  //wait for other threads to init before dropping priveledges
  while(!output_thread_init)
  {
  	usleep(conn_ring_poll_interval);
  }
  
  while((!error_thread_init) && (error_interval > 0))
  {
  	usleep(conn_ring_poll_interval);
  }
  
  while((!stats_thread_init) && (stats_interval > 0))
  {
  	usleep(conn_ring_poll_interval);
  }
    
  
  //do setuid here!
  //Notice, this program is not designed to be safe on non-linux systems nor be safe as an setuid program.
  if (user != NULL)
  {
  		struct passwd *pw_entry = NULL;
  		if ((getuid() != 0) && (geteuid() != 0))
      {
      	DIE("You must start as root to switch users");
			}
      
      //look up user id and group id
      if (!(pw_entry = getpwnam(user)))
      {
      	DIE("Could not look up user_id for %s", user);
			}
      //look up additional groups (extra credit)
      if (initgroups(user, pw_entry->pw_gid))
      {
      	DIE("Could not look up additional groups for %s", user);
			}
      //Actually setuid and setgid
      if (setgid(pw_entry->pw_gid))
      {
      	 DIE("Could not setgid for %s", user);
      }
      if (setuid(pw_entry->pw_uid))
      {
      	 DIE("Could not setuid to %s", user);
      }
      /* Make sure both effective and real user and group were set correctly */
      if ((getuid() != pw_entry->pw_uid) || (geteuid() != pw_entry->pw_uid) || (getgid() != pw_entry->pw_gid) || (getegid() != pw_entry->pw_gid))
      {
      	DIE("Attempted setuid and setgid didn't work correctly\nPossibly non-Linux or program used suid (no gauruntee of security)");
      }
	}
  
   
  nids_register_tcp(tcp_callback);
  program_state = 1;
  nids_run();
  program_state = 2;
  DEBUG(30,"Libnids Run Finished");
  
  
#ifdef WITH_BSF
  if (bsf_enabled)
  {
  	bsf_destroy(bsf_desc);
	}
#endif
  //Wait for all the other threads to exit before exiting
  //wait_for_other_threads();
  
  
    pthread_join(writer_thread_h, NULL);
    if (error_interval > 0)
    {
  	    pthread_join(error_thread_h, NULL);
    } else
    {
        //Provide some useful output/feedback to users.
        print_errors();
        if ( errors.tcp_limit > 0)
        {
            WARN("Hint--TCP_LIMIT: Streams dropped due to insufficient connection hash table. Consider increasing connection hash size (-s).");
        }
        if ( errors.tcp_queue > 0)
        {
            WARN("Hint--TCP_QUEUE: Investigate possible packet loss (if PCAP_LOSS is 0 check ifconfig for RX dropped).");
        }
        if ( errors.tcp_hdr > connection_id)
        {
            WARN("Hint--TCP_HDR: Possible checksum failures? See disable checksum option (-k).");
        }
        if ( errors.vtx_ring > 0)
        {
            WARN("Hint--VTX_RING: Streams dropped due to insufficent stream ring buffer. Try increasing ring size (-Q) and/or decreasing poll interval (-R) or increaseing speed of temp dir (-t) (ex. use /dev/shm instead of disk).");
        }
        
    }
    if (stats_interval > 0)
    {
  	    pthread_join(stats_thread_h, NULL);
    } else
    {
        //Provide some useful output/feedback to users.
        print_stats();
    
        if ( closed_connections_limit > 0)
        {
            WARN("Hint--VTX_LIMIT: Streams truncated due to size limits. If not desired, adjust stream size limits accordingly (-C, -S).");
        }
    
    }
  
  
  return 0;
}
