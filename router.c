#include <queue.h>
#include "skel.h"
#include <stdint.h>

#define WORD_LEN 32

struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

struct arp_entry {
    __u32 ip;
    uint8_t mac[6];
};

int calculate_line ( char *file) {
	char line[70];
	int counter = 0;
	FILE *sursa;
	sursa = fopen(file, "r");
	if (sursa < 0 ){
		printf("Nu pot deschide fisierul");
	}
	while (fgets(line, sizeof(line), sursa) != NULL) {
		memset(line, 0, 69 * sizeof(char));
		counter++;
	}
	fclose(sursa);
	return counter;
}

struct route_table_entry *get_best_route(__u32 dest_ip, struct route_table_entry *rtable, int rtable_size) {
	struct route_table_entry entr;
	int i = 0;
	int route = -1;

	for (i = 0; i < rtable_size; i++){
		entr = rtable[i];
		if ( (entr.mask & dest_ip) == entr.prefix ) {
			if( (route == -1 ) || (rtable[i].mask > rtable[route].mask))
				route = i;
		}
	}
	if (route != -1)
		return &rtable[route];
		else
		return NULL;
}


int parser_rtable(struct route_table_entry *rtable , char *file, int number_line) {
	struct in_addr ip_addr;
	char *p;
	char line[300];
	int line_index = 0;
	FILE *sursa;
	sursa = fopen(file, "r");
	if (sursa < 0 ){
		printf("Nu pot deschide fisierul");
	}

	while (fgets(line, 299 , sursa) != NULL) {
		p = strtok(line, " ");
		inet_aton(p, &ip_addr);
		rtable[line_index].prefix = ip_addr.s_addr;	
		p = strtok(NULL, " ");
		inet_aton(p, &ip_addr);
		rtable[line_index].next_hop = ip_addr.s_addr;
		p = strtok(NULL, " ");
		inet_aton(p, &ip_addr);
		rtable[line_index].mask = ip_addr.s_addr;
		p = strtok(NULL, " ");
		rtable[line_index].interface = atoi(p);
		p = strtok(NULL, " ");
		line_index++;
	}
	fclose(sursa);
	return line_index;
}

struct arp_entry *get_arp_entry(__u32 ip, struct arp_entry *arp_table, int arp_table_len)  {

    for (int i = 0; i < arp_table_len; i++) {
    	if (ip == arp_table[i].ip) {
    		return &arp_table[i];
    	}
    }
    return NULL;
}
struct arp_entry *arp_table;
int arp_table_len;

void parse_arp_table() 
{
    FILE *f;
    fprintf(stderr, "Parsing ARP table\n");
    f = fopen("arp_table.txt", "r");
    DIE(f == NULL, "Failed to open arp_table.txt");
    char line[100];
    int i = 0;
    for(i = 0; fgets(line, sizeof(line), f); i++) {
        char ip_str[50], mac_str[50];
        sscanf(line, "%s %s", ip_str, mac_str);
        fprintf(stderr, "IP: %s MAC: %s\n", ip_str, mac_str);
        arp_table[i].ip = inet_addr(ip_str);
        int rc = hwaddr_aton(mac_str, arp_table[i].mac);
        DIE(rc < 0, "invalid MAC");
    }
    arp_table_len = i;
    fclose(f);
    fprintf(stderr, "Done parsing ARP table.\n");
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);

	packet m;
	int rc;

	init(argc - 2, argv + 2);

	fprintf(stderr, "alou");

	int number_line = calculate_line(argv[1]);
	struct route_table_entry *rtable = (struct route_table_entry*) malloc( (number_line + 1) * sizeof(struct route_table_entry));

	int aux = 0;
	aux = parser_rtable(rtable, argv[1], number_line);
	queue q = queue_create();
	struct in_addr ip_addr;
	int arp_capac = 25;
	arp_table_len = 0;
	arp_table = (struct arp_entry*) malloc (arp_capac* sizeof(struct arp_entry));
	parse_arp_table();



	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		
		struct ether_header *ethdr = (struct ether_header *) m.payload; 
		switch (ntohs(ethdr->ether_type)) {
			case ETHERTYPE_IP: {
				struct iphdr *ip_hdr = (struct iphdr *) (m.payload + sizeof(struct ether_header));
				inet_aton(get_interface_ip(m.interface), &ip_addr);
				struct icmphdr *icmp_hdr = parse_icmp(m.payload);
				if (ip_hdr->daddr == ip_addr.s_addr && icmp_hdr->type == 8) {
					send_icmp(ip_hdr->saddr, ip_hdr->daddr, ethdr->ether_dhost, ethdr->ether_shost, 0, 0, m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
					
					continue;
				}

				if (ip_hdr->ttl <= 1) {
					send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, ethdr->ether_dhost, ethdr->ether_shost, ICMP_TIME_EXCEEDED, 0, m.interface);
					continue;
				}

				if (ip_checksum(ip_hdr, sizeof(struct iphdr))) {
					continue;
				}
				ip_hdr->ttl--;
				ip_hdr->check = 0;
				ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));	
				
				struct route_table_entry *rte = get_best_route(ip_hdr->daddr, rtable, number_line);
				if (rte == NULL) {
					send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, ethdr->ether_dhost, ethdr->ether_shost, ICMP_DEST_UNREACH, 0, m.interface);
				}

				struct arp_entry *entry_arp = get_arp_entry(rte->next_hop, arp_table, arp_table_len);
				
				if (entry_arp == NULL) {
					continue;
				}

				get_interface_mac(rte->interface, ethdr->ether_shost);
				memcpy(ethdr->ether_dhost, entry_arp->mac, 6);
				send_packet(rte->interface, &m);
				
				
				continue;
			}
			
			case ETHERTYPE_ARP: {
		
					break;
			}
		}
		
		
		}
		return 0;
	}
