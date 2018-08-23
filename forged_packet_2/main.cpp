#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 
#endif
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "winsock2.h"
#include "Mswsock.h"
#include "declaration.h"
#include "iostream"
using namespace std;



extern int abcd;     //external global int

/*#define abc
#ifndef _WINDOWS_
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif*/

#ifndef HAVE_REMOTE
#define WPCAP
#define HAVE_REMOTE
#endif
#include <pcap.h>
int main(int argc, char*argv[])
{


	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	u_int inum, i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	//int res;
	//struct pcap_pkthdr *header;
	//const u_char *pkt_data;

    printf("pktdump_ex: prints the packets of the network using WinPcap.\n");
    printf("   Usage: pktdump_ex [-s source]\n\n"
           "   Examples:\n"
           "      pktdump_ex -s file://c:/temp/file.acp\n"
           "      pktdump_ex -s rpcap://\\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998}\n\n");

    if(argc < 3)
    {

        printf("\nNo adapter selected: printing the device list:\n");
        /* The user didn't provide a packet source: Retrieve the local device list */
        if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
        {
            fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
            return -1;
        }
        
        /* Print the list */
        for(d=alldevs; d; d=d->next)
        {
            printf("%d. %s\n    ", ++i, d->name);

            if (d->description)
                printf(" (%s)\n", d->description);
            else
                printf(" (No description available)\n");
        }
        
        if (i==0)
        {
            fprintf(stderr,"No interfaces found! Exiting.\n");
            return -1;
        }
        
        printf("Enter the interface number (1-%d):",i);
        scanf("%d", &inum);
        
        if (inum < 1 || inum > i)
        {
            printf("\nInterface number out of range.\n");

            /* Free the device list */
            pcap_freealldevs(alldevs);
            return -1;
        }
        
        /* Jump to the selected adapter */
        for (d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
        
        /* Open the device */
        if ( (fp= pcap_open(d->name,
                            100 /*snaplen*/,
                            PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
                            20 /*read timeout*/,
                            NULL /* remote authentication */,
                            errbuf)
                            ) == NULL)
        {
            fprintf(stderr,"\nError opening adapter\n");
            return -1;
        }
    }
    else 
    {
        // Do not check for the switch type ('-s')
        if ( (fp= pcap_open(argv[2],
                            100 /*snaplen*/,
                            PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
                            20 /*read timeout*/,
                            NULL /* remote authentication */,
                            errbuf)
                            ) == NULL)
        {
            fprintf(stderr,"\nError opening source: %s\n", errbuf);
            return -1;
        }
    }



	//(size_forge()).a;

	

	const unsigned char *p1;
	p1=Send_forged();
	if(abcd==82)
		cout<<"THIS IS IT: "<<abcd<<"\n\n\n\n";
	
	if (pcap_sendpacket(fp,p1 ,abcd/* size */) != 0)
    {
		cout<<"*:*"<<abcd<<endl<<endl;
		
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
        return 1;
    }
	

	///////////////////////
	

	//Send_forged();

	/*unsigned char abc[]="\x45\x00\x00\x28\x77\x58\x40\x00\x2A\x06\x17\x74\xd4\x44\x2c\x13\xc0\xa8\x01\x04";
	unsigned char ak[]={0X45,0X00,0x00,0x28,0x77,0x58,0x40,0x00,0x2A,0x06,0x00,0x00,0xD4,0x44,0x2C,0x13,0xC0,0xA8,0x01,0x04};
	unsigned short i2=checksum((unsigned short*)ak,sizeof(ak));

	char a='a';
	unsigned long long int ak47=(unsigned long long int)(a);
	cout<<std::hex<<ak47;*/
	//cout<<std::hex<<i;






  return 1;
}