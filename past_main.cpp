#include "ethernethelper.h"
#include "arphelper.h"
#include "iphelper.h"
#include "tcphelper.h"
#include "udphelper.h"
#define NO 0

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void analyzePacket(struct pcap_pkthdr* header, const u_char* packet){
    printf("========================================\n");
    printf("============ PACKET CAPTURED ===========\n");
    printf("========================================\n");
    printf("packet total size : %u\n", header->caplen);
    int32_t index = 0;
    int32_t version = 0;

    //----------------datalink layer---------------------
    void* ether;
    ethernetHeader* etherHeader;
    index = readEthernet(packet, &ether, &version);
    if(index >= 0 && version == ethernetV2){
        etherHeader = (ethernetHeader*)ether;
        version = etherHeader->type;
        printEthernet(etherHeader);
    }
    else{
        printf("\tsorry. Ethernet IEEE802.3 is not provided\n");
        return;
    }

    //----------------network layer---------------------
    if(version == ARP){
        arpHeader arpHeader;
        index += readArp(packet+index, &arpHeader);
        version = NO;
        printArp(&arpHeader);
        return;
    }
    else if(version == IP){
        ipHeaderV4 ipHeader;
        index += readIp(packet+index, &ipHeader);
        version = ipHeader.protocol;
        printIp(&ipHeader);
    }
    else {
        printf("\tsorry. this protocol is not provided\n");
    }

   //--------------transport layer---------------------
    if(version == TCP){
        tcpHeader tcp;
        index += readTcp(packet + index, &tcp);
        printTcp(&tcp);
    }
    else if(version == UDP){
        udpHeader udp;
        index += readUdp(packet + index, &udp);
        printUdp(&udp);
    }
    else {
        printf("\tsorry, this protocol is not provided\n");
    }

    //------------ data ----------------------------------
    int dataSize = header->caplen - index;
    if(dataSize > 10) dataSize = 10;
    printf("\t===== data =====\n\t");
    printf("length : %d\n\t", dataSize);
    for(int i = 0; i < dataSize; i++)
        printf("%02x ", packet[index + i]);
    printf("\n");
}

void isArpRequest(struct pcap_pkthdr* header, const u_char* packet){
	
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
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    analyzePacket(header, packet);
  }

  pcap_close(handle);
  return 0;
}
