#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#define DEBUG 0

void interrupt_handler(int signal) {
    exit(0);
}

pcap_t *pcap_handle;

char errbuf[PCAP_ERRBUF_SIZE];
int header_len;

/*DEBUG FUNCTION*/
pcap_handler print(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Get the current time
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t current_time = tv.tv_sec;
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&current_time));
    printf("%s.%06ld ", timestamp, tv.tv_usec);

    // Process the packet data here
    printf("Packet captured, size: %d\n", header->len);
    return 0;
}


void print_help( char *prog_name) {
    printf("Usage: %s [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n", prog_name);
    printf("\n");
    printf("Options:\n");
    printf("  -i, --interface interface   Set the interface to capture packets from\n");
    printf("  -p, --port port             Set the port to filter packets on (requires --tcp or --udp)\n");
    printf("  -t, --tcp                   Filter TCP packets\n");
    printf("  -u, --udp                   Filter UDP packets\n");
    printf("      --arp                   Filter ARP packets\n");
    printf("      --icmp4                 Filter ICMPv4 packets\n");
    printf("      --icmp6                 Filter ICMPv6 packets\n");
    printf("      --igmp                  Filter IGMP packets\n");
    printf("      --mld                   Filter MLD packets\n");
    printf("  -n, --num num               Set the number of packets to capture before exiting\n");
}

char* filter(int port, int tcp, int udp, int arp, int icmp4, int icmp6, int igmp, int mld) {
    char *filter = (char*) malloc(100); // allocate 100 bytes of memory
    strcpy(filter, "");
    if (port != 0){
        char tmp[50] = "";
        if(tcp)
        {
            sprintf(tmp, "tcp %d ", port);
            strcat(filter, tmp);
        }
        if(udp)
        {
            memset(tmp, 0, sizeof(tmp));
            sprintf(tmp, "udp %d ", port);
            strcat(filter, tmp);
        }
        if(arp)
            strcat(filter, "arp or ");
        if(icmp4)
            strcat(filter, "icmp or ");
        if(icmp6)
            strcat(filter, "icmp6 or ");
        if(igmp)
            strcat(filter, "igmp or ");
        if(mld)
            strcat(filter, "mld or ");
    }
    else {
        if(tcp) {
            strcat(filter, "tcp or ");
        }
        if(udp) {
            strcat(filter, "udp or ");
        }
        if(arp) {
            strcat(filter, "arp or ");
        }
        if(icmp4) {
            strcat(filter, "icmp or ");
        }
        if(icmp6) {
            strcat(filter, "icmp6 or ");
        }
        if(igmp) {
            strcat(filter, "igmp or ");
        }
        if(mld) {
            strcat(filter, "mld or ");
        }
    }
    // Remove the last " or " from the filter string
    if (strlen(filter) > 4) {
        filter[strlen(filter)-4] = '\0';
    }
    if(DEBUG) {
        printf("filter contains:%s\n", filter);
    }
    return filter;
}

pcap_t* open_pcap_socket(char *device, const char* packet_filter){
    
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_if_t *devices;

    struct bpf_program pcap_filter;

    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    if(DEBUG){    
        printf("Available devices:\n");
        for (pcap_if_t *d = devices; d != NULL; d = d->next) {
            printf("%s\n", d->name);
        }
    }
    device = devices->name;
    printf("chosen device: %s\n", device);

    // Open network interface to capture packets
    //4th param is timeout, setting to 0 is no timeout set

    pcap_handle = pcap_open_live(device, BUFSIZ, 1, 1, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        exit(EXIT_FAILURE);   
    }

    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, errbuf);
        exit(EXIT_FAILURE);   
    }
    
    if (pcap_compile(pcap_handle, &pcap_filter, (char *) packet_filter, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(pcap_handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(pcap_handle, &pcap_filter) < 0) {
        fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(pcap_handle));
        exit(EXIT_FAILURE);
    }
    return pcap_handle;
}

void socket_sniffer(pcap_t* pcap_handle){

    //datalink layer
    int data_layer_type;

    data_layer_type = pcap_datalink(pcap_handle);
    if (data_layer_type < 0){
        fprintf(stderr, "pcap_datalink() error \n");
        exit(0);
    }
    //datalink layer header size
    switch (data_layer_type){
        case DLT_NULL:
            header_len = 4;
            break;

        case DLT_EN10MB:
            
            header_len = 14;
            break;
        case DLT_SLIP:
        case DLT_PPP:
            
            header_len = 24;
            break;

        case DLT_LINUX_SLL:
            
            header_len = 16;
            break;

        default:
            fprintf(stderr, "Unsupported header (%d)\n", data_layer_type);
            return;
    }
}

pcap_handler parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
 
// Extract Ethernet header
const struct ether_header *eth_hdr;
eth_hdr = (struct ether_header *) packet;

// Extract source and destination MAC addresses
char src_mac[18], dst_mac[18];
sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
printf("src MAC: %s\n", src_mac);
printf("dst MAC: %s\n", dst_mac);

// Extract IP header
const struct iphdr *ip_hdr;
ip_hdr = (struct iphdr *) (packet + sizeof(struct ether_header));

// Extract source and destination IP addresses
char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
inet_ntop(AF_INET, &(ip_hdr->saddr), src_ip, INET_ADDRSTRLEN);
inet_ntop(AF_INET, &(ip_hdr->daddr), dst_ip, INET_ADDRSTRLEN);
printf("src IP: %s\n", src_ip);
printf("dst IP: %s\n", dst_ip);

// Extract TCP header
const struct tcphdr *tcp_hdr;
tcp_hdr = (struct tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct iphdr));

// Extract source and destination port numbers
uint16_t src_port, dst_port;
src_port = ntohs(tcp_hdr->source); //16 bits nthos
dst_port = ntohs(tcp_hdr->dest);
printf("src port: %d\n", src_port);
printf("dst port: %d\n", dst_port);
printf("\n\n");
/*

    // Check if packet is TCP or UDP
    int is_tcp = (ip6hdr->protocol == IPPROTO_TCP);
    int is_udp = (ip6hdr->protocol == IPPROTO_UDP);

    // Check if packet should be filtered by port number
    int filter_by_port = port_num > 0;

    // Filter packet by port number if necessary
    int src_port = -1, dst_port = -1;
    if (filter_by_port && (is_tcp || is_udp)) {
        tcp_hdr = (struct tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct iphdr));
        udp_hdr = (struct udphdr *) (packet + sizeof(struct ether_header) + sizeof(struct iphdr));
        src_port = is_tcp ? ntohs(tcp_hdr->source) : ntohs(udp_hdr->source);
        dst_port = is_tcp ? ntohs(tcp_hdr->dest) : ntohs(udp_hdr->dest);
        if (src_port != port_num && dst_port != port_num) {
            return;
        }
    }

    // Filter packet by port number if necessary
    if (tcp_hdr && udp_hdr && port_num) {
        if (tcp_hdr->th_sport != port_num && tcp_hdr->th_dport != port_num && udp_hdr->uh_sport != port_num && udp_hdr->uh_dport != port_num) {
            return;
        }
    } else if (tcp_hdr && port_num) {
        if (tcp_hdr->th_sport != port_num && tcp_hdr->th_dport != port_num) {
            return;
        }
    } else if (udp_hdr && port_num) {
        if (udp_hdr->uh_sport != port_num && udp_hdr->uh_dport != port_num) {
            return;
        }
    }

    // Print packet information
    printf("timestamp: %s", ctime((const time_t*)&header->ts.tv_sec));
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
    printf("frame length: %d bytes\n", header->len);

    if (is_tcp) {
        printf("src IP: %s\n", inet_ntoa(ip6hdr->saddr));
        printf("dst IP: %s\n", inet_ntoa(ip6hdr->daddr));
        printf("src port: %d\n", ntohs(tcp_hdr->th_sport));
        printf("dst port: %d\n", ntohs(tcp_hdr->th_dport));
    } else if (is_udp) {
        printf("src IP: %s\n", inet_ntoa(ip6hdr->saddr));
        printf("dst IP: %s\n", inet_ntoa(ip6hdr->daddr));
        printf("src port: %d\n", ntohs(udp_hdr->uh_sport));
        printf("dst port: %d\n", ntohs(udp_hdr->uh_dport));
    }
    */
    return 0;
}

int main(int argc, char *argv[]) {
    char *interface = NULL;
    int port = 0;
    int tcp = 0;
    int udp = 0;
    int arp = 0;
    int icmp4 = 0;
    int icmp6 = 0;
    int igmp = 0;
    int mld = 0;
    int num = 0;
    char* device;
    char* packet_filter;

    // set up a signal handler for ctrl+c
    signal(SIGINT, interrupt_handler);

    static struct option long_options[] = {
        {"interface", optional_argument, 0, 'i'},
        {"port", required_argument, 0, 'p'},
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"arp", no_argument, 0, 0},
        {"icmp4", no_argument, 0, 0},
        {"icmp6", no_argument, 0, 0},
        {"igmp", no_argument, 0, 0},
        {"mld", no_argument, 0, 0},
        {"num", required_argument, 0, 'n'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;
    while ((c = getopt_long(argc, argv, "hi:p:t::u::n:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'h':
                print_help(argv[0]);
                exit(0);
                break;
            case 'i':
                interface = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 't':
                tcp = 1;
                break;
            case 'u':
                udp = 1;
                break;
            case 0:
                if (strcmp("arp", long_options[option_index].name) == 0)
                    arp = 1;
                else if (strcmp("icmp4", long_options[option_index].name) == 0)
                    icmp4 = 1;
                else if (strcmp("icmp6", long_options[option_index].name) == 0)
                    icmp6 = 1;
                else if (strcmp("igmp", long_options[option_index].name) == 0)
                    igmp = 1;
                else if (strcmp("mld", long_options[option_index].name) == 0)
                    mld = 1;
                break;
            case 'n':
                num = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s [-i interface] [-p port] [-t|-u] [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] [-n num]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    packet_filter = filter(port, tcp, udp, arp, icmp4, icmp6, igmp, mld);
    if (pcap_handle = open_pcap_socket(interface, packet_filter)) {
        socket_sniffer(pcap_handle);
                                                //    pcap handler print works!!!
        int packets_captured = pcap_loop(pcap_handle, 0, (pcap_handler) parse_packet, NULL);
        if (packets_captured == -1) {
            fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(pcap_handle));
            exit(EXIT_FAILURE);
        }
        printf("Captured %d packets\n", packets_captured);
    // stats of packets
        struct pcap_stat stats;

        // print the stats (if some exist)
        if (pcap_stats(pcap_handle, &stats) >= 0) {
            printf("%d packets received\n", stats.ps_recv);
            printf("%d packets dropped\n", stats.ps_drop);
        }

        // close the pcap descriptor
        pcap_close(pcap_handle);
        printf("Captured %d packets\n", packets_captured);
    }

    // Do something with the parsed options
    printf("interface: %s\n", interface);
    printf("port: %d\n", port);
    printf("tcp: %d\n", tcp);
    printf("udp: %d\n", udp);
    printf("arp: %d\n", arp);
    printf("icmp4: %d\n", icmp4);
    printf("icmp6: %d\n", icmp6);
    printf("igmp: %d\n", igmp);
    printf("n: %d\n", num);
    
    return 0;
}



/*
// Assume packet is a character array containing the packet data
// and packet_length is the length of the packet in bytes
pcap_handler parse_packet(const uint8_t *packet, size_t packet_length) {
    printf("Packet too short.\n");
    // Check packet length
    if (packet_length < 4) {
        printf("Packet too short.\n");
        return;
    }
    // Extract header fields
    uint16_t magic_number = (packet[0] << 8) | packet[1];
    uint16_t version = (packet[2] << 8) | packet[3];

    // Print header fields
    printf("Magic number: 0x%04X\n", magic_number);
    printf("Version: %u\n", version);

    // Parse payload
    size_t payload_offset = 4;
    size_t payload_length = packet_length - payload_offset;

    return NULL;
    // TODO: Add code to parse the payload
}
*/