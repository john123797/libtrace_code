/* Libtrace program designed to demonstrate the use of the trace_get_source_*
 * shortcut functions. 
 *
 * This code also contains examples of sockaddr manipulation.
 */
#include "libtrace.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "header/link_list_counting.h"

IPnode *ip_table[10000];

long long int get_ip(struct sockaddr *ip)
{
	struct in_addr source_ip_addr;
	
	if (ip->sa_family == AF_INET) {
		struct sockaddr_in *v4 = (struct sockaddr_in *)ip;
		source_ip_addr=v4->sin_addr;
	}

	return ntohl(source_ip_addr.s_addr);
}

void per_packet(libtrace_packet_t *packet)
{
	
	struct sockaddr_storage addr;
	struct sockaddr *addr_ptr;

	int x;

	addr_ptr = trace_get_source_address(packet, (struct sockaddr *)&addr);

	x = Hash_Function(get_ip(addr_ptr));
	
	Linklist_Update(ip_table, x, get_ip(addr_ptr));
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

	/* Ensure we have at least one argument after the program name */
        if (argc < 2) {
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

	Linklist_Init(ip_table,10000);

        while (trace_read_packet(trace,packet)>0) {
                per_packet(packet);
        }

	printf("Total = %d\n", Linklist_Distinct(ip_table));
	Linklist_Destroy(ip_table);

        if (trace_is_err(trace)) {
                trace_perror(trace,"Reading packets");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        libtrace_cleanup(trace, packet);
        return 0;
}

