#include "libtrace.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "header/fm.h"
#include "header/link_list_counting.h"
#include <math.h>

#define SEED 10128227

FM_type *fm;
IPnode *ip_table[10000];
uint32_t next_report = 0;

long long int get_ip(struct sockaddr *ip)
{
	struct in_addr source_ip_addr;
	
	if (ip->sa_family == AF_INET) {
		struct sockaddr_in *v4 = (struct sockaddr_in *)ip;
		source_ip_addr=v4->sin_addr;
	}

	return ntohl(source_ip_addr.s_addr);
}

void per_packet(libtrace_packet_t *packet, int table, int time)
{
	
	struct sockaddr_storage addr;
	struct sockaddr *addr_ptr;
	struct timeval ts;	
	float x;

	addr_ptr = trace_get_source_address(packet, (struct sockaddr *)&addr);
	ts = trace_get_timeval(packet);
	x = get_ip(addr_ptr);

	if (next_report == 0)
	{
		next_report = ts.tv_sec + time;
		printf("Time\t\tFM count\tLink count\terror\n");
	}

	while (ts.tv_sec > next_report) {
		x = ((float)Linklist_Distinct(ip_table)-(float)FM_Distinct(fm))/(float)Linklist_Distinct(ip_table);
		printf("%u\t%f\t%d\t\t%f %%\n", next_report, FM_Distinct(fm), Linklist_Distinct(ip_table), fabs(x)*100);
		
		FM_Destroy(fm);
		Linklist_Destroy(ip_table);
		fm = FM_Init(table, SEED);
		Linklist_Init(ip_table, 10000);
		
		next_report += time;
	}

	FM_Update(fm,get_ip(addr_ptr));
	Linklist_Update(ip_table, Hash_Function(get_ip(addr_ptr)), get_ip(addr_ptr));	
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
	float x;
	int time,table;

	/* Ensure we have at least one argument after the program name */
        if (argc < 4) {
                fprintf(stderr, "Usage: %s inputURI, FM_table, time\n", argv[0]);
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

	time = atoi(argv[3]);
	table = atoi(argv[2]);

	printf("\nThe number of FM table : %d\n", table);
	printf("The time interval is   : %d\n\n", time);

	fm = FM_Init(table, SEED);
	Linklist_Init(ip_table,10000);

        while (trace_read_packet(trace,packet)>0) {
                per_packet(packet,table,time);
        }

        if (trace_is_err(trace)) {
                trace_perror(trace,"Reading packets");
                libtrace_cleanup(trace, packet);
                return 1;
        }
	
	x = ((float)Linklist_Distinct(ip_table)-(float)FM_Distinct(fm))/(float)Linklist_Distinct(ip_table);	
	printf("%u\t%f\t%d\t\t%f %%\n\n", next_report, FM_Distinct(fm), Linklist_Distinct(ip_table), fabs(x)*100);

        FM_Destroy(fm);
	Linklist_Destroy(ip_table);
	libtrace_cleanup(trace, packet);
        return 0;
}

