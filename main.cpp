#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void print_mac(char *name, uint8_t *mac) {
    printf("%s = %02x:%02x:%02x:%02x:%02x:%02x\n", name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(char *name, uint8_t *ip) {
    printf("%s = %d.%d.%d.%d\n", name, ip[0], ip[1], ip[2], ip[3]);
}

void print_port(char *name, uint8_t *p) {
    printf("%s = %d\n", name, (p[0] << 8) + p[1]);
}

void print_data(uint8_t *p, unsigned int len) {
    int min = -1;
    min = 16 < len ? 16 : len;
    for(int i=0;i<min;i++)
        printf("%02x ", p[i]);
    printf("\n");
}

int main(int argc, char* argv[]) {
    
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);
        
        struct libnet_ethernet_hdr *ethernet = (struct libnet_ethernet_hdr*) packet;
        print_mac("src mac", ethernet->ether_shost);
        print_mac("dst mac", ethernet->ether_dhost);
        
        if (ntohs(ethernet->ether_type) != ETHERTYPE_IP) {
            printf("It's not an IPv4 packet!\n");
            continue;
        }

        packet += sizeof(struct libnet_ethernet_hdr);
        struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr*) packet;
        print_ip("src ip",(uint8_t *) &ip->ip_src);
        print_ip("dst ip",(uint8_t *) &ip->ip_dst);

        if(ip->ip_p != IPPROTO_TCP){
            printf("It's not an TCP packet!\n");
            continue;
        }
            
        packet += sizeof(struct libnet_ipv4_hdr);
        struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr*) packet;
        print_port("src port",(uint8_t *) &tcp->th_sport);
        print_port("dst port",(uint8_t *) &tcp->th_dport);

        packet += (tcp->th_off * sizeof(uint32_t));
        unsigned int left_len = header->caplen - sizeof(struct libnet_ethernet_hdr) - sizeof(struct libnet_ipv4_hdr) - (tcp->th_off * sizeof(uint32_t));
        printf("left lenghth : %u\n", left_len);
        print_data((uint8_t *)packet, left_len);
    }

    pcap_close(handle);
    return 0;
}
