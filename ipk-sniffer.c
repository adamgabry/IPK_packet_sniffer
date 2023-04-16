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

pcap_t *pcap_handle;
char errbuf[PCAP_ERRBUF_SIZE];

pcap_t* open_pcap_socket(char *device){
    
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, errbuf);
        net = 0;
        mask = 0;
    }
    // Open network interface to capture packets
    
    pcap_handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return 1;
    }
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



    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
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

    char* device;

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
    open_pcap_socket(interface);

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
