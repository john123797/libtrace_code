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

#define seed 10128227

CM_type *cm_1;
CM_type *cm_2;
uint64_t count_wire_count = 0;
uint64_t interval_wire_count = 0;
uint32_t next_report = 0;
uint32_t first_report = 0;
uint64_t IP_table[10000] = {0};
FILE *fp;

long long int get_ip(struct sockaddr *ip)
{
	struct in_addr source_ip_addr;
	
	if (ip->sa_family == AF_INET) {
		struct sockaddr_in *v4 = (struct sockaddr_in *)ip;
		source_ip_addr=v4->sin_addr;
	}

	return ntohl(source_ip_addr.s_addr);
}

void print_ip(unsigned int IP, int time)
{
	int a,b,c,d;

	a = IP%256;
	b = (IP/256)%256;
	c = (IP/256/256)%256;
	d = (IP/256/256/256)%256;
	printf("Time = %d \tIP = %d.%d.%d.%d \tspecific value = %f\n", time, d, c, b, a,(float)CM_PointEst(cm_2,IP)/(float)count_wire_count);
	fprintf(fp, "%d.%d.%d.%d\n",d, c, b, a);
}

void per_packet(libtrace_packet_t *packet, int length, int hash, float threshold, int time)
{
	
	struct sockaddr_storage addr;
	struct sockaddr *addr_ptr;
	struct timeval ts;

	uint64_t wire_count = 0;
	unsigned int IP;
	int i;

	addr_ptr = trace_get_source_address(packet, (struct sockaddr *)&addr);
	ts = trace_get_timeval(packet);
	wire_count = trace_get_wire_length(packet);
	IP = get_ip(addr_ptr);

	if(next_report == 0)
	{
		next_report = ts.tv_sec + time;
		first_report = next_report;
	}

	if(ts.tv_sec > next_report)
	{
		first_report = next_report;		
		cm_2 = cm_1;
		CM_Destroy(cm_1);
		cm_1 = CM_Init(length,hash,seed);
		count_wire_count = interval_wire_count;
		interval_wire_count = 0;
		next_report += time;
	}
	
	interval_wire_count += wire_count;
	CM_Update(cm_2,IP,wire_count);	
	
	if(ts.tv_sec > first_report)
	{
		if((float)CM_PointEst(cm_2,IP)/(float)count_wire_count > threshold)
		{
			for (i=0;i<=10000;i++)
			{
				if(IP_table[i]==0)
				{
					IP_table[i]=IP;			
					print_ip(IP,ts.tv_sec);
					break;
				}
				else if(IP==IP_table[i]) break;
			}
		}  
	}
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
	
	int length,hash,time;
	float threshold;
	fp = fopen("Si_HH_list.txt","w");

	/* Ensure we have at least one argument after the program name */
        if (argc < 6) {
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
	time = atoi(argv[5]);

	printf("\nThe number of CM hashfunction : %d\n", hash);
	printf("The number of entry is   : %d\n", length);
	printf("The time interval is   : %d\n", time);
	printf("The threshold is   : %f\n\n", threshold);

	cm_1 = CM_Init(length,hash,seed);
	cm_2 = CM_Init(length,hash,seed);

        while (trace_read_packet(trace,packet)>0) {
                per_packet(packet, length, hash, threshold, time);
        }

	

        if (trace_is_err(trace)) {
                trace_perror(trace,"Reading packets");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        libtrace_cleanup(trace, packet);
	fclose(fp);
        return 0;
}

