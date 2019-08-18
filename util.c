#include "util.h"

uint16_t my_ntohs(const u_char* num) {
   // int _num = *num;
    uint16_t _num = *(const uint16_t*)num;
    return _num << 8 | _num >> 8;
}

uint32_t my_ntohl(const u_char* num) {
    uint32_t _num = *(const uint32_t*)num;
    return _num << 24 | _num >> 24 | (_num&0xff00) << 8 | (_num&0xff0000) >> 8;
}

void my_mac_converter(uint8_t* mac){
	for(int i =0 , j = 6; i < 3, j >=3; i++, j--){
		uint8_t tmp = mac[i]; 
		mac[i] = mac[j];
		mac[j] = tmp;  
	}
}

void printHexValue(const char* msg, uint8_t* start, int32_t size, const char delim){
  printf("%s", msg);
  for(int i = 0; i < size-1; i++)
    printf("%02x%c", start[i], delim);
  printf("%02x\n", start[size-1]);
}

void printDecValue(const char* msg, uint8_t* start, int32_t size, const char delim){
  printf("%s", msg);
  for(int i = 0; i <size-1; i++)
    printf("%d%c", start[i], delim);
  printf("%d\n", start[size-1]);
}

bool getIp(uint8_t ip[4], char* dev){
	int sock; 
	struct ifreq ifr; 
	struct sockaddr_in *sin; 
	sock = socket(AF_INET, SOCK_STREAM, 0); 
	if(sock < 0){
		printf("util.h _ getIp _ socket error\n"); 
		return false;  
	}

	strcpy(ifr.ifr_name, dev); 
	if(ioctl(sock, SIOCGIFADDR, &ifr) < 0){
		printf("util.h _ getIp _ iotcl error\n"); 
		return false; 
	}
	sin = (struct sockaddr_in*)&ifr.ifr_addr; 
	memcpy(ip, &(sin->sin_addr), 4); 
	return true; 
}

bool getMac(uint8_t mac_address[6],char* dev){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { printf("socek error\n");};

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { printf("getmac_ erro set ioctl\n");  }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { printf("getmac _ error ioctl\n"); }
    }

//    unsigned char mac_address[6];

    if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
    if (success) return true; 
}

/*bool getMac(uint8_t mac[6], char* dev){
	int sock; 
	struct ifreq ifr;  
	sock = socket(AF_INET, SOCK_STREAM, 0); 
	if(sock < 0){
		printf("util.h _ getMac _ iotcl error\n"); 
		return false; 
	}
	strcpy(ifr.ifr_name, dev); 
	if(ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		printf("util.h _ getMac _ ioctol error\n"); 	
		return false; 
	}
	struct ifreq* it = ifr.ifc_req; 
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6); 
	struct ifreq ifr; 
	struct ifconf ifc; 
	char buf[1024]; 
	int success = 0; 
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP); 
	if(sock == -1) {
		printf("util.h _ getMac _ socker err\n"); 
		return false; 
	}

	struct ifreq* it = ifc.ifc_req; 
	const struct ifreq* const end = it + (ifc.ifc_len /sizeof(struct ifreq)); 

	for(; it != end ; it++){
		strcpy(ifr.ifr_name, it->ifr_name); 
		if(ioctl(sock, SIOCGIFFLAGS, &ifr) == 0){
			if(!(ifr.ifr_flags & IFF_LOOPBACK)){
				if(ioctl(sock, SIOCGIFHWADDR, &ifr) == 0){
					success = 1; 
					break; 
				}
			}
		}
		else{
			printf("util.h _ ioctl error \n"); 
		}
	}
	if(success) memcpy(mac, ifr.ifr_hwaddr.sa_data, 6); 
	
	return true; 
}*/

bool getgateway(uint8_t addr[4]){
	long destination, gateway; 
	char iface[IF_NAMESIZE]; 
	char buf[4096]; 
	FILE* file; 

	memset(iface, 0, sizeof(iface)); 
	memset(buf, 0, sizeof(buf)); 
	
	file = fopen("/proc/net/route", "r"); 
	if(file < 0){
		printf("util.h _ getgatewat _ file open error");
		return 0;  
	}

	while(fgets(buf, sizeof(buf), file)){
		if(sscanf(buf, "%s %lx %lx", iface, &destination, &gateway) == 3){
			if(destination == 0){
				memcpy(addr,&gateway, 4); 
				fclose(file); 
				return true; 
			}
		}
	}
	return false; 
}

void usage() {
  printf("syntax: pcap_test <interface> <sender ip> <target ip> <sender ip> <target ip>...\n");
	printf("sample: pcap_test wlan0 192.168.2.121 192.168.2.1\n");
	printf("==================================================\n");
	printf("sender means the one you want to change arp table!\n");
	printf("target means the one you wnat to write sender's arp table!\n");
}

int basicSetting(int argc, char* argv[]){
  if (argc >= 4 && argc%2 != 0) {
	  usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	getIp(ip, dev);
	printDecValue("[+] ip : ", ip, 4, '.');
	getMac(mac, dev);
	printHexValue("[+] mac : ", mac, 6, ':');
	printf("argc is %d\n", argc);

	sessionSize= argc/2 -1; 
	sessionNumber = (int*) malloc(sizeof(int)*sessionSize); 
	for(int i= 0; i < sessionSize; i++) 
		sessionNumber[i] = i; 
	pthread_mutex_init(&mutex, NULL);
	threadSignal = (int*)malloc(sizeof(int)*(sessionSize));
	for(int i = 0; i < sessionSize; i++) 
		threadSignal[i] = 0; 
	ipsets = (ip_set*) malloc(sizeof(int)*(sessionSize)); 
	return 1;
}

