/*
*
* Copyright 2009-2011 Lockheed Martin Corporation
* 
* The xpipes program is open source software: you can copy it, redistribute it and/or modify
* it under the terms of the GNU General Public License version 2.0 as published by
* the Free Software Foundation.  The xpipes Program and any derivatives of the xpipes program 
* must be licensed under GPL version 2.0 and may not be licensed under GPL version 3.0.
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY OF ANY KIND, including without limitation the implied warranties of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details at http://www.gnu.org/licenses/gpl-2.0.html.
* 
* The term "xpipes" should be taken to also include any portions or derived works of xpipes.  
* 
* You are highly encouraged to send your changes to the xpipes program to 
* opensource.tools.security@lmco.com for possible incorporation into the main distribution.  
* By sending these changes to Lockheed Martin, you are granting to Lockheed Martin 
* Corporation the unlimited, perpetual, non-exclusive right to reuse, modify, 
* and/or relicense the code on a royalty-free basis.
* 
* The libraries to which xpipes links are distributed under the terms of their own licenses.  
* Please see those libraries for their applicable licenses.
*
*/

/*
* xpipes
* a simple utilitity for multiplexing pipes
* this is intended to be used in conjunction with vortex to create multithreaded analyzers
* gcc xpipes.c -lpthread -Wall -o xpipes -O2
*/



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <pthread.h>
#include <unistd.h>


#define MAX_NUM_PROCS 1000
#define MAX_NUM_PROCS_DIGITS 16


/*
TODO:
set cpu affinity for children (per child or as a group). If you do that, probably have to do setuid also (since root is required for setting affinity).
*/


struct list_element_t
{
  struct list_element_t *next;
  //taken from linux/limits.h
  char buffer[PATH_MAX+1];
};

struct list_metadata_t
{
    struct list_element_t *head;
    int count;
};

char *process_name;

int num_list_elements = 0;
int num_procs = 10;
int num_procs_initialized = 0;
//these are tunables, current defaults
unsigned int consumer_bottleneck_poll_interval = 10;  //time in us
unsigned int list_elements_per_proc = 10;


int input_done = 0;
int ensure_exit = 0;

char *command = NULL;
const char popen_type[] = "w";

struct list_metadata_t free_list;
struct list_metadata_t ready_list;

//for getopt
extern int optind;
extern int opterr;
extern int optopt;
extern char *optarg;

pthread_mutex_t list_mtx;

pthread_mutex_t data_ready_mtx;
pthread_cond_t data_ready_cv;


void grablock(void)
{
  if (pthread_mutex_lock(&list_mtx) != 0)
  {
    fprintf(stderr, "error getting mutex lock\n");
    //exit(2);
  }
}

void releaselock(void)
{
  if (pthread_mutex_unlock(&list_mtx) != 0)
  {
    fprintf(stderr, "error releasing mutex lock\n");
  }    
}

void wait_data_ready(void)
{
    pthread_mutex_lock(&data_ready_mtx);
    pthread_cond_wait(&data_ready_cv, &data_ready_mtx);
    pthread_mutex_unlock(&data_ready_mtx);
    
}

void signal_data_ready(void)
{
    pthread_mutex_lock(&data_ready_mtx);
    pthread_cond_signal(&data_ready_cv);
    pthread_mutex_unlock(&data_ready_mtx);
}

void broadcast_data_ready(void)
{
    pthread_mutex_lock(&data_ready_mtx);
    pthread_cond_broadcast(&data_ready_cv);
    pthread_mutex_unlock(&data_ready_mtx);
}


void print_usage()
{
    fprintf(stderr,"Usage: %s -f file | -c command [-h] [-P num procs] [ -e ] [ -Q count ] [ -R usec ]\n\n", process_name);
    fprintf(stderr,
            "   -h              Print this help message and exit\n"
            "   -f file         file containing command to execute\n"
            "   -c command      Don't forget to quote if necessary. Command is interpreted by shell.\n"
            "   -e              Ensure exit (don't hang) even if children hang\n"
            "   -P  procs       Set number of processes to spawn (default: 10, max: %i)\n"
            "   -Q  count       Number of lines to buffer per proc (default: %i)\n"
            "   -R  usec        Wait period if consumers become bottleneck (increase to limit CPU lost to polling) (default: %i)\n"
            "\n"
            "for each child process that xpipes creates, it sets the environment variable XPIPES_INDEX to a unique value.\n"
            "this value can be used inside of command and will be interpretted by the shell.\n"
            "\n", MAX_NUM_PROCS, list_elements_per_proc, consumer_bottleneck_poll_interval);
}


//get length of list
int list_length(struct list_metadata_t *list_p)
{
    return list_p->count;   
}

//remove something from head of list
struct list_element_t *list_remove(struct list_metadata_t *list_p)
{
    struct list_element_t *temp_element = NULL;
    if (list_p->count < 1)
    { 
        return NULL;
    } else
    {
        temp_element = list_p->head;
        list_p->head = temp_element->next;
        list_p->count--;
        temp_element->next = NULL;
        return temp_element;
    }
    
}


//add something to tail of list
void list_add(struct list_metadata_t *list_p, struct list_element_t *element_p)
{
    struct list_element_t *temp_element = list_p->head;
    if (list_p->count > 0)
    {
        while ( temp_element->next != NULL )
        {
            temp_element = temp_element->next;
        }
        temp_element->next = element_p;
        element_p->next = NULL;
        list_p->count++;
        
    } else
    {
        list_p->head = element_p;
        list_p->count = 1;
    }
}



//function for writer threads. 
void *writer_thread(void *arg)
{
    
    FILE *output_fh;
    int proc_id;
    struct list_element_t *element;
    int tmp;
    
    char proc_id_str[MAX_NUM_PROCS_DIGITS+1];
    proc_id_str[0] = '\0';
    
    grablock();
    proc_id = num_procs_initialized;
    num_procs_initialized++;
    
    
    //Set ENV
    if (snprintf(proc_id_str, MAX_NUM_PROCS_DIGITS, "%i", proc_id) > 0)
    {
        setenv( "XPIPES_INDEX", proc_id_str, 1);
    }
    
    
    //If you want to do cpu affinity locking, priorities, etc, do it here!
    
    output_fh = popen(command, popen_type); 

    if (output_fh == NULL)
    {
        fprintf(stderr,"popen failed!\n");
        exit(3);
    }
   
    //make out line buffered   
    setvbuf(output_fh, NULL, _IOLBF, 0); 
        
    //fprintf(stderr,"Initialzied proc %i \n",num_procs_initialized);
    
    releaselock();
        
    
    while (input_done == 0)
    {
        
            
        wait_data_ready();
        
        grablock();
        if (list_length(&ready_list) > 0)
        {
            element = list_remove(&ready_list);
            releaselock();
            
            if (element != NULL)
            {
                tmp = fprintf(output_fh, "%s", element->buffer);
                
                if (tmp < strlen(element->buffer))
                {
                    fprintf(stderr,"Error printing whole string to pipe\n");
                }
                if (tmp < 0)
                {
                    fprintf(stderr,"Pipe %i broken\n", proc_id);    
                    pclose(output_fh);
                    pthread_exit(NULL);
                }
                            
                element->buffer[0] = '\0';
                grablock();
                list_add(&free_list, element);
                releaselock();
            
            }
         
        } else
        {
            releaselock();
        }
        
        
    }
    
    //flush any data in pipe
    
    
    if (ensure_exit == 1)
    {
        //give consumers fair chance to consume data, but don't hang infinately
        usleep(1000);
    } else
    {
        //this can make us hang 
        fflush(output_fh);
    }
    
    //do pclose
    pclose(output_fh);
    pthread_exit(NULL);
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
				return 0;
			}
			
			
			//Get file length
			fseek(filter_file_fp, 0, SEEK_END);
			filter_file_len=ftell(filter_file_fp);
			fseek(filter_file_fp, 0, SEEK_SET);
			
			//Allocate memory
			*filter_buffer=(char *)calloc(1,(filter_file_len+1));
			if (!*filter_buffer)
			{
				return 0;
			}
			
			
			//Read file contents into buffer
			if (fread(*filter_buffer, filter_file_len, 1, filter_file_fp) != 1)
			{
				free(*filter_buffer);
				return 0;
			}
			
			fclose(filter_file_fp);
			
			//Null terminate
			(*filter_buffer)[filter_file_len] = '\0';
			
			
			return filter_file_len;
}



int main (int argc, char **argv)
{
	
    int i;
    int tmp;
    struct list_element_t *temp_element_p;
    int opt;
    process_name = argv[0];

    pthread_mutex_init(&list_mtx, NULL);
    pthread_mutex_init(&data_ready_mtx, NULL);
    pthread_cond_init(&data_ready_cv, NULL);

    pthread_t thread_refs[MAX_NUM_PROCS];


	
	
    //get command line options
    while ((opt = getopt(argc, argv, "hP:c:f:eQ:R:")) != -1)
    {
        switch (opt) 
        {
		    case 'c':
                command = optarg;
                break;
            case 'e':
                ensure_exit = 1;
                break;
            case 'f':
                if ( read_file_into_buffer(optarg,&command) == 0)
                {    
                    exit(2);
                }
                break;
            case 'P':
                num_procs = atoi(optarg);
                if (num_procs > MAX_NUM_PROCS) num_procs = MAX_NUM_PROCS; 
                break;
            case 'R':
                consumer_bottleneck_poll_interval = atoi(optarg);
                break;
        
            case 'Q':
                list_elements_per_proc = atoi(optarg);
                break;
        
            default:
                print_usage();
                fprintf(stderr,"Invalid option %c\n", opt);
                exit(2);
                break;
  	
        }
    }
	
	
	//too many args or too few
    if (argc > optind || argc < 2)
    {
        print_usage();
        fprintf(stderr,"Invalid command line options\n");
    }
    
    //make sure there is a command to run
    if ( command == NULL )
    {
        fprintf(stderr, "You must specify a command to run\n");
        print_usage();
  	    exit(2);
    }
  
    if (consumer_bottleneck_poll_interval < 0)
    {
        print_usage();
        fprintf(stderr,"Invalid Wait Period\n");
        exit(2);    
    }
  
    if (list_elements_per_proc < 1)
    {
        print_usage();
        fprintf(stderr,"Invalid line buffer size\n");
        exit(2);    
    }
  
    if (num_procs < 1)
    {
        print_usage();
        fprintf(stderr,"Invalid number of processes\n");
        exit(2);    
    }
  
  
    num_list_elements = num_procs * list_elements_per_proc;
  
      //intialize the list elements and lists
    for (i = 0; i < num_list_elements; i++)
    {
        //malloc each element and set link
        temp_element_p = (struct list_element_t *) malloc(sizeof(struct list_element_t));
        if (temp_element_p == NULL)
        {     
  	        fprintf(stderr, "Malloc failed.\n");
  	        exit(2);
        }
        list_add(&free_list, temp_element_p);
    }
  
//now start up the threads.


    for (i=0; i < num_procs; i++)
    {
        tmp = pthread_create(&thread_refs[i], NULL, writer_thread, NULL);    
        if (tmp != 0 )
        {    
            fprintf(stderr, "pthread create failed for proc %i with return value of: %i.\n", i, tmp);
  	        exit(2);
        }
    }


    

    
    grablock();
    temp_element_p = list_remove(&free_list);
    releaselock();
  
    //loop through each line of input
    while(fgets(temp_element_p->buffer, PATH_MAX, stdin) != NULL)
    {
        grablock();
        list_add(&ready_list, temp_element_p);
        temp_element_p = list_remove(&free_list);
        releaselock();
        
        signal_data_ready();
        
        //if we are backed up, signal again
        if (list_length(&free_list) < (num_list_elements/2))
        {
            broadcast_data_ready();
        }
        
        //wait if we don't have any free list elements available, keep signalling all the while
        while (temp_element_p == NULL)
        {
            usleep(consumer_bottleneck_poll_interval);
            broadcast_data_ready();
            grablock();
                temp_element_p = list_remove(&free_list);
            releaselock();
        }
        
    }
	
	//wait for ready_list to empty
	while(list_length(&ready_list) > 0)
	{
	    signal_data_ready();
	}
	
	input_done = 1;

    
    //make sure no one is stuck on condition variable
    broadcast_data_ready();

    
    //fprintf(stderr, "Done processing input, finishing up\n");
        
    //join all the writer threads
    for (i=0; i < num_procs; num_procs++)
    {
        pthread_join(thread_refs[i], NULL);
    }

    exit(0);

}	


