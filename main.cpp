#include <pcap.h>
#include <stdio.h>
#include <string.h>

int ip_check(const u_char * packet){
    if(packet[12] == 0x08 && packet[13] == 0x00){
        return 1;
    }
    return 0;
}

int tcp_check(const u_char * packet){
    if(packet[23] == 6){
        return 1;
    }
    return 0;
}

void ds_mac_print(const u_char * packet){
    char d_mac[25];
    char s_mac[25];

    sprintf(d_mac, "D_mac == %02x:%02x:%02x:%02x:%02x:%02x", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    sprintf(s_mac, "s_mac == %02x:%02x:%02x:%02x:%02x:%02x", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    printf("%s\n", s_mac);
    printf("%s\n", d_mac);
}

void ds_ip_print(const u_char * packet){
    char d_ip[30];
    char s_ip[30];

    sprintf(s_ip, "S_IP == %d.%d.%d.%d", packet[14+12], packet[14+13], packet[14+14], packet[14+15]);
    sprintf(d_ip, "D_IP == %d.%d.%d.%d", packet[14+16], packet[14+17], packet[14+18], packet[14+19]);


    printf("%s\n", s_ip);
    printf("%s\n", d_ip);
}

void ds_port_print(const u_char * packet){
    char d_port[20];
    char s_port[20];

    sprintf(s_port, "S_PORT == %d", packet[34] * 256 + packet[35]);
    sprintf(d_port, "D_PORT == %d", packet[36] * 256 + packet[37]);

    printf("%s\n", s_port);
    printf("%s\n", d_port);
}

void ds_data_print(const u_char * packet, struct pcap_pkthdr* header){
    bpf_u_int32 data_len = header ->len; // test_code
    char data_insert[13];

    // printf("data len == %d\n",header -> len);

    if(data_len == 54){
        printf("DATA == None\n");
    }
    else {
        printf("DATA == ");
        for(int i = 0;i < data_len - 53;i++) {
            printf("%02x ", packet[54+i]);
            if(i==9){
                break;
            }
        }
        printf("\n");
    }
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}



int main(int argc, char* argv[]) {


  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    int i = 0;
    struct pcap_pkthdr* header;
    const u_char* packet;
    bpf_u_int32 packet_len = header -> caplen;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\n", header->caplen);

    if (ip_check(packet)){
        if(tcp_check(packet)){
            ds_mac_print(packet);
            ds_ip_print(packet);
            ds_port_print(packet);
            ds_data_print(packet, header);
            printf("--------------\n");
        }
    }
  }

  pcap_close(handle);
  return 0;
}
