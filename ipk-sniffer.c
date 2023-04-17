#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
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
#include <stdbool.h>
#include <sys/time.h>
#include <time.h>

#define DEBUG 0

//variable used to handle packet capture (libpcap lib)
pcap_t *pcap_handle;

//SIGINT signal or more known - user call this signal with CTRL-C
void interrupt_handler(int signal) {
    pcap_close(pcap_handle);
    printf("\nSuccesfull signal exit\n");
    exit(EXIT_SUCCESS);
}
//BUFSIZ is the maximum size of a packet,
char errbuf[PCAP_ERRBUF_SIZE];

//global header_len variable, passing through all fctions
//better as global variable
int header_len;


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

/**
 * @brief filter function to make filter based on the given params from user input
 * @brief filter is compatible to work with pcap functions, mainly pcap_compile,
 * @cite to set filter right for our: https://www.devdungeon.com/content/using-libpcap-c#filters
 * 
 * @param port 
 * @param tcp 
 * @param udp 
 * @param arp 
 * @param icmp4 
 * @param icmp6 
 * @param igmp 
 * @param mld 
 * @return char* 
 */
char* filter(int port, int tcp, int udp, int arp, int icmp4, int icmp6, int igmp, int mld) {
    char *filter = (char*) malloc(100); // allocate 100 bytes of memory
    strcpy(filter, "");
    if (port != 0){
        char tmp[50] = "";
        if(tcp)
        {
            sprintf(tmp, "(tcp port %d) or ", port);
            strcat(filter, tmp);
        }
        if(udp)
        {
            memset(tmp, 0, sizeof(tmp)); //setting tmp to zero after using it in tcp option
            sprintf(tmp, "(udp port %d) or ", port);
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

/**
 * @brief scans for available devices and returns device
 * 
 * @param device 
 * @return char* 
 */
char* available_device(char *device){
    pcap_if_t *devices;
    // Find all available network devices, or exit the program if an error occurs.
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    // if device is NULL, print all available devices
    if (device == NULL) {
        printf("Available devices:\n");
        for (pcap_if_t *d = devices; d != NULL; d = d->next) {
            printf("%s\n", d->name);
        }
        exit(EXIT_SUCCESS);
    }
    //goes in a loop and if given device is in a list of available devices, sets flag to true
    bool is_valid_device = false;
    for (pcap_if_t *d = devices; d != NULL; d = d->next) {
        if (strcmp(device, d->name) == 0){
            is_valid_device = true;
            break;
        }
    }
    if(!is_valid_device){
            printf("Not an available interface %s\n\n", device);
            printf("Available interfaces:\n");
            for (pcap_if_t *d = devices; d != NULL; d = d->next) {
                printf("%s\n", d->name);
            }
        }
    // If no device given is enabled, print out the names of all available network devices.
    return device;
}

/**
 * @brief This function opens a pcap socket on the specified network device and sets a packet filter on it.
 * @brief The function returns the pcap handle if successful, or exits the program if it fails. 
 * @param device 
 * @param packet_filter 
 * @return pcap_t* pcap_handle
 */
pcap_t* open_pcap_socket(char *device, const char* packet_filter){
    
    // Declare variables to store 
    bpf_u_int32 mask;       //network mask 
    bpf_u_int32 net;        //IP address
    pcap_if_t *devices;     //available network devices.

    // Declare a struct to hold packet filter.
    struct bpf_program pcap_filter;

    // If no specific device was provided, use the first available device.
    device = available_device(device);

    // Open a network interface to capture packets
    // and the two 1s indicate that we want to start capturing immediately and to capture in promiscuous mode.
    pcap_handle = pcap_open_live(device, BUFSIZ, 1, 1, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "err:  Couldn't open device %s: %s\n", device, errbuf);
        exit(EXIT_FAILURE);   
    }

    // Get the network mask and IP address of the selected device.
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, errbuf);
        exit(EXIT_FAILURE);   
    }
    
    // Compile the packet filter using the provided filter expression and the network mask.
    if (pcap_compile(pcap_handle, &pcap_filter, (char *) packet_filter, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(pcap_handle));
        exit(EXIT_FAILURE);
    }

    // Apply the compiled packet filter to the network interface.
    if (pcap_setfilter(pcap_handle, &pcap_filter) < 0) {
        fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(pcap_handle));
        exit(EXIT_FAILURE);
    }

    // Return the pcap handle variable.
    return pcap_handle;
}

/**
 * @brief Get the data layer object
 * 
 * @param pcap_handle 
 */
void get_data_layer(pcap_t* pcap_handle){

    //datalink layer
    int data_layer_type;

    data_layer_type = pcap_datalink(pcap_handle);

    // check if getting datalink layer type was successful
    if (data_layer_type < 0){
        fprintf(stderr, "pcap_datalink() error \n");
        exit(0);
    }
    //datalink layer header size based on the datalink layer type
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
            // unsupported datalink layer type
            fprintf(stderr, "Unsupported header (%d)\n", data_layer_type);
            return;
    }
}
//sources for inspiration on this function:
// https://stackoverflow.com/questions/5177879/display-the-contents-of-the-packet-in-c
// https://www.opensourceforu.com/2011/02/capturing-packets-c-program-libpcap/
/**
 * @brief prints packet content
 * 
 * @param addr 
 * @param length 
 */
void printPacketContent(const void *addr, int length) {
    int i;
    unsigned char buff[17]; // buffer to store ASCII representation of packet content
    unsigned char *pc = (unsigned char *)addr; // cast void pointer to unsigned char pointer

    for (i = 0; i < length; i++) {
        if ((i % 16) == 0) {
            // print previous line's ASCII representation before starting a new line
            if (i != 0)
                printf("  %s\n", buff);

            // print current line's offset in hexadecimal
            printf("0x%04x: ", i);
        }
        // print current byte's hexadecimal representation
        printf(" %02x", pc[i]);
        // add current byte's ASCII representation to buffer
        //if char is nonprintable:
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) { 
            buff[i % 16] = '.'; // use '.' for non-printable characters
        }
        else {
            buff[i % 16] = pc[i]; // use the printable character itself for printable characters
        }
        // print the ASCII representation of the current line
        if ((i % 16) == 15 || i == length - 1) {
            buff[(i % 16) + 1] = '\0'; // terminate the buffer with null
            printf("  %s", buff);
        }
    }
}

/**
 * @brief function for printing right packet info
 * 
 * @param args 
 * @param header 
 * @param packet 
 * @return 0 
 */
pcap_handler parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    char timestamp[30]; // allocate space for timestamp string
    struct tm* tm_info;
    time_t ts_sec = header->ts.tv_sec;
    int ts_usec = header->ts.tv_usec;
    tm_info = localtime(&ts_sec);
    strftime(timestamp, 30, "%Y-%m-%dT%H:%M:%S", tm_info);
    //3 digits for microseconds
    sprintf(timestamp + strlen(timestamp), ".%03d", ts_usec/1000);
    strftime(timestamp + strlen(timestamp), 30 - strlen(timestamp), "%z", tm_info);

    // Extract Ethernet header
    // Same for UDP, TCP, and ARP
    const struct ether_header *eth_hdr;
    eth_hdr = (struct ether_header *) packet;

    // Extract source and destination MAC addresses
    // Same for UDP, TCP, and ARP
    char src_mac[18], dst_mac[18];
    sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
    sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

    //inspiration: https://stackoverflow.com/questions/3060950/how-to-get-ip-address-from-sock-structure-in-c
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    // Extract IP header
    const struct iphdr *ip_hdr;
    ip_hdr = (struct iphdr *) (packet + sizeof(struct ether_header));
    inet_ntop(AF_INET, &(ip_hdr->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->daddr), dst_ip, INET_ADDRSTRLEN);

    // Extract TCP header
    //how to correctly set tcp_hdr: https://cboard.cprogramming.com/c-programming/67961-get-tcp-source-port.html
    const struct tcphdr *tcp_hdr;
    tcp_hdr = (struct tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct iphdr));

    // Extract source and destination ports
    uint16_t src_port, dst_port;

    // Extract IP header for udp and tcp
    if(eth_hdr->ether_type == htons(ETHERTYPE_IP)){

        const uint32_t len = header->len;
        printf("Timestamp: %s\n", timestamp);
        printf("src MAC: %s\n", src_mac);
        printf("dst MAC: %s\n", dst_mac);
        printf("frame length: %d\n", header->len);
        // Extract source and destination IP addresses
        printf("src IP: %s\n", src_ip);
        printf("dst IP: %s\n", dst_ip);
        
        // numbers of ports available here: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        switch (ip_hdr->protocol)
        {
        case 6://TCP IV4
            // Extract source and destination port numbers
            src_port = ntohs(tcp_hdr->source); //16 bits nthos
            dst_port = ntohs(tcp_hdr->dest);
            printf("src port: %d\n", src_port);
            printf("dst port: %d\n", dst_port);
            printf("\n");
            printPacketContent(packet, len);
            printf("\n\n");
            break;
            
        case 17: //UDP IPV4
            // Extract source and destination port numbers
            src_port = ntohs(tcp_hdr->source); //16 bits ntohs
            dst_port = ntohs(tcp_hdr->dest);
            printf("src port: %d\n", src_port);
            printf("dst port: %d\n", dst_port);
            printf("\n");
            printPacketContent(packet, len);
            printf("\n\n");
            break;
        default:
            break;
        }
    }
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

    //setting packet filter
    packet_filter = filter(port, tcp, udp, arp, icmp4, icmp6, igmp, mld);

    //opening socket in given interface using packet_filter
    if (pcap_handle = open_pcap_socket(interface, packet_filter)) {
        
        get_data_layer(pcap_handle);

        // loop num times and call parse_packet function
        int packets_captured = pcap_loop(pcap_handle, num, (pcap_handler) parse_packet, NULL);
        if (packets_captured == -1) {
            fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(pcap_handle));
            exit(EXIT_FAILURE);
        }
        // close the pcap descriptor
        pcap_close(pcap_handle);
    }

    if(DEBUG){
        // statistics for packets
        struct pcap_stat stats;
        // print stats
        if (pcap_stats(pcap_handle, &stats) >= 0) {
            printf("%d packets received\n", stats.ps_recv);
            printf("%d packets dropped\n", stats.ps_drop);
        }
        printf("interface: %s\n", interface);
        printf("port: %d\n", port);
        printf("tcp: %d\n", tcp);
        printf("udp: %d\n", udp);
        printf("arp: %d\n", arp);
        printf("icmp4: %d\n", icmp4);
        printf("icmp6: %d\n", icmp6);
        printf("igmp: %d\n", igmp);
        printf("n: %d\n", num);
    }
    return 0;
}