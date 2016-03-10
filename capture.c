
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "netpkghdr.h"

unsigned char g_buffer[BUFF_MAX_LEN] = {0};

pcap_t* get_pcap( const char* name )
{
    pcap_if_t* ifs;
    pcap_if_t* d;
    pcap_t* pcap;
    char errbuff[PCAP_ERRBUF_SIZE];
    char *device = "eth0";
    char errbuf[1024];

    if ((device = pcap_lookupdev(errbuf)) == NULL)
    {
        perror(errbuf);
        return NULL;
    }
    else
        printf("device: %s\n", device);

    pcap = pcap_open_live( device, \
                           BUFF_MAX_LEN, \
                           0, \
                           3000, \
                           errbuff );

    pcap_freealldevs( ifs );

    if ( pcap == NULL )
    {
        fprintf( stderr, "pcap_open_live [%s]\n", errbuff );
        return NULL;
    }

    return pcap;
}

int main()
{
    int rc;
    pcap_t* pcap;
    struct bpf_program bpf;
    struct pcap_pkthdr* header;
    const unsigned char* pkt_data;


    eth_hdr* eth;

    ip_hdr* ip;
    unsigned short ip_hdr_len;

    tcp_hdr* tcp;
    unsigned short tcp_hdr_len;
    unsigned short tcp_data_len;
    unsigned char* tcp_pkt_data;


    if ( ( pcap = get_pcap( "eth0" ) ) == NULL )
    {
        return -1;
    }

    printf( "**********************************************\n\n" );


    if ( pcap_compile( pcap, &bpf, "tcp", 1, 0 ) < 0 )
    {
        fprintf( stderr, "pcap_compile error\n" );
        return -1;
    }

    if ( pcap_setfilter( pcap, &bpf ) < 0 )
    {
        fprintf( stderr, "pcap_setfilter\n" );
        return -1;
    }


    while ( ( rc = pcap_next_ex( pcap, &header, &pkt_data ) ) >= 0 )
    {
        if ( rc == 0 )
        {
            continue;
        }

        eth = ( eth_hdr* )pkt_data;

        ip = ( ip_hdr* )( eth + 1 );
        ip_hdr_len = ( ( ip->ver_ihl & 0x0F ) << 2 );

        tcp = ( tcp_hdr* )( pkt_data + sizeof( eth_hdr ) + ip_hdr_len );
        tcp_hdr_len = ( ( tcp->len_code & 0x00F0 ) >> 2 );
        tcp_data_len = header->len - sizeof( eth_hdr ) - ip_hdr_len - tcp_hdr_len;
        tcp_pkt_data = ( unsigned char* )tcp + tcp_hdr_len;


        /*        if ( tcp_data_len < 3 || \
                        ( strncmp( ( char* )tcp_pkt_data, "GET", 3 ) && \
                          strncmp( ( char* )tcp_pkt_data, "POST", 4 ) && \
                          strncmp( ( char* )tcp_pkt_data, "HTTP/1.1", 8 ) ) )
                {
                    continue;
                }*/

        memcpy( g_buffer, tcp_pkt_data, tcp_data_len );
        g_buffer[tcp_data_len] = 0;

        printf(" MAC : %02X-%02X-%02X-%02X-%02X-%02X", eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
        printf(" --> %02X-%02X-%02X-%02X-%02X-%02X\n", eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5]);

        printf(" IP  : %d.%d.%d.%d:%d", ip->saddr.b1, ip->saddr.b2, ip->saddr.b3, ip->saddr.b4, ntohs(tcp->sport));
        printf(" --> %d.%d.%d.%d:%d\n", ip->daddr.b1, ip->daddr.b2, ip->daddr.b3, ip->daddr.b4, ntohs(tcp->dport));


        printf(" 长度: %d\n\n Hex:\n", header->len);

        //显示数据帧内容
        int i;
        for (i = 0; i < (int)header->len; ++i)  {
            printf(" %02x", pkt_data[i]);
            if ( (i + 1) % 16 == 0 )
                printf("\n");
        }

        printf( "\n\n" );
        printf( "%s\n", ( char* )g_buffer );
        printf( "**********************************************\n\n" );
    }

    pcap_close( pcap );

    return 0;
}