#include "libtrace.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "header/countmin.h"
#include "header/link_list_counting.h"

#define seed 123456789

CM_type *cm;
IPnode *ip_table[10000];
uint64_t all_wire_count = 0;

long long int get_ip(struct sockaddr *ip)
{
	struct in_addr source_ip_addr;
	
	if (ip->sa_family == AF_INET) {
		struct sockaddr_in *v4 = (struct sockaddr_in *)ip;
		source_ip_addr=v4->sin_addr;
	}

	return ntohl(source_ip_addr.s_addr);
}

void count_heavyhitter(IPnode **Table,float threshold)
{
	int i=0,a,b,c,d;
	IPnode *temp;

	for (i=0;i<=10000;i++)
	{
		temp =Table[i];

		while(temp!=NULL)
		{      
			if((float)CM_PointEst(cm,temp->ip)/(float)all_wire_count > threshold)
			{
				a = temp->ip%256;
				b = (temp->ip/256)%256;
				c = (temp->ip/256/256)%256;
				d = (temp->ip/256/256/256)%256;
				printf("IP = %d.%d.%d.%d  \tspecific value = %f\n", d, c, b, a, (float)CM_PointEst(cm,temp->ip)/(float)all_wire_count);
			}  
       			temp = temp->link;
		}
	}
}

void per_packet(libtrace_packet_t *packet)
{
	
	struct sockaddr_storage addr;
	struct sockaddr *addr_ptr;

	uint64_t wire_count = 0;
	unsigned int IP;

	addr_ptr = trace_get_source_address(packet, (struct sockaddr *)&addr);
	wire_count = trace_get_wire_length(packet);
	
	IP = get_ip(addr_ptr);
	all_wire_count += wire_count;

	Linklist_Update(ip_table, Hash_Function(IP), IP);
	
	CM_Update(cm,IP,wire_count);
}

void libtrace_cleanup(libtrace_t *trace, libtrace_packet_t *packet) {

        /* It's very important to ensure that we aren't trying to destroy
         * a NULL structure, so each of the destroy calls will only occur
         * if the structure exists */
        if (trace)
                trace_destroy(trace);

        if (packet)
                trace_destroy_packet(packet);

}

int main(int argc, char *argv[])
{
        /* This is essentially the same main function from readdemo.c */

        libtrace_t *trace = NULL;
        libtrace_packet_t *packet = NULL;
	
	int length,hash;
	float threshold;
	
	/* Ensure we have at least one argument after the program name */
        if (argc < 5) {
                fprintf(stderr, "Usage: %s inputURI\n", argv[0]);
                return 1;
        }

        packet = trace_create_packet();

        if (packet == NULL) {
                perror("Creating libtrace packet");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        trace = trace_create(argv[1]);

        if (trace_is_err(trace)) {
                trace_perror(trace,"Opening trace file");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        if (trace_start(trace) == -1) {
                trace_perror(trace,"Starting trace");
                libtrace_cleanup(trace, packet);
                return 1;
        }

	hash = atoi(argv[2]);
	length = atoi(argv[3]);
	threshold = atof(argv[4]);

	printf("\nThe number of CM hashfunction : %d\n", hash);
	printf("The number of entry is   : %d\n", length);
	printf("The threshold is   : %f\n\n", threshold);

	cm = CM_Init(length,hash,seed);
	Linklist_Init(ip_table,10000);

        while (trace_read_packet(trace,packet)>0) {
                per_packet(packet);
        }
	
	count_heavyhitter(ip_table, threshold);

	CM_Destroy(cm);
	Linklist_Destroy(ip_table);

        if (trace_is_err(trace)) {
                trace_perror(trace,"Reading packets");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        libtrace_cleanup(trace, packet);
        return 0;
}

