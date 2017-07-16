
#include <stdio.h>
#include <stdlib.h>
#include "pcap.h"
#include <arpa/inet.h>

#define SIZE_ETHERNET 14


/*
struct pcap_pkthdr{
    struct timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};
*/

struct ether_hdr{
    u_char ether_dmac[6];
    u_char ether_smac[6];
    u_short ether_type;
};

struct ip_hdr{
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_tlen;
    u_short ip_id;
    u_short ip_offset;
    u_char ip_ttl;
    u_char ip_protocol;
    u_short ip_check;
    struct in_addr ip_src, ip_dst;
};

#define IP_HL(ip) (((ip)->ip_vhl) >> 4)

struct tcp_hdr{
    u_short tcp_srcp;
    u_short tcp_detp;
    u_int tcp_seqnum;
    u_int tcp_acknum;
    u_char tcp_offset_rsvd;
    u_char tcp_flags;
    u_short tcp_win;
    u_short tcp_check;
    u_short tcp_urgp;
};

#define TCP_OFF(tcp) (((tcp)->tcp_offset_rsvd & 0xf0) >> 4)

int main(){

    //u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)

    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "port 80";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;
    const u_char *res;    

    const struct ether_hdr *ethernet;
    const struct ip_hdr *ip;
    const struct tcp_hdr *tcp;
    const char *payload;

    u_int size_ip;
    u_int size_tcp;

    //pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf);
    //int pcap_compile(pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 netmask)
    //int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
    //int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
    //void got_packet(u_char *args, cont struct pcap_pkthdr, *header, const u_char *packet)

    dev = pcap_lookupdev(errbuf);
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev ,errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    while((res = pcap_next_ex(handle, &header, &packet) >= 0)){

        if (res == 0)
            continue;

        ethernet = (struct ehter_hdr*)(packet);

        ip = (struct ip_hdr*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;

        if (size_ip < 16){
            printf("Invalid IP header length : %u bytes\n", size_ip);
            continue;
        }

        tcp = (struct tcp_hdr*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TCP_OFF(tcp)*4;
        if (size_tcp < 20){
            printf("Invalid TCP header length : %u bytes\n", size_tcp);
            continue;
        }

        payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);


        printf("\n");
        printf("Sorce Mac Address:          ");
        for (i = 0; i< 6; i++){
            printf("%02x", ethernet->ether_smac[i]);
            if(i<5){
                printf(":");
            }
        }printf("\n");
        printf("Destination Mac Address:    ");
        for (i = 0; i< 6; i++){
            printf("%02x", ethernet->ether_dmac[i]);
            if(i<5){
                printf(":");
            }
        }printf("\n");

        //(int)strtol(szHex, NULL, 16)

        printf("-------------------------------------------------\n");
        printf("Sorce IP Address:           %s\n", inet_ntoa(ip->ip_src));
        printf("Destination IP Address:     %s\n", inet_ntoa(ip->ip_dst));
        printf("-------------------------------------------------\n");
        printf("Sorce Port:                 %x\n", tcp->tcp_srcp);
        printf("Destination Port:           %x\n", tcp->tcp_detp);
        printf("-------------------------------------------------\n");
        printf("Data:\n%s\n", payload);
        printf("-------------------------------------------------\n");

    }

    if(res == -1){
        fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(handle));
        return -1;
    }

    pcap_close(handle);

    return 0;
}
