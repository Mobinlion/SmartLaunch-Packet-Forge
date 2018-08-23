// packetDump_sendforge.cpp : Defines the entry point for the console application.
//
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "Winsock2.h"      //must call winsock2.h first or error ensues!
#include "Mswsock.h"



#include <stdlib.h>
#include <stdio.h>
#include "fstream"
#include "iostream"
#include "declaration.h"


using namespace std;



fstream test;
const unsigned char* globe;
extern int abcd;
bool repeat=false;
//
// NOTE: remember to include WPCAP and HAVE_REMOTE among your
// preprocessor definitions.
//

#include <pcap.h>

const unsigned char * tcpcheck(const unsigned char *p,unsigned int i)
{

	bool client=false;
	unsigned short sourceport=0;
	unsigned short destport=0;
	sourceport=ntohs(*(unsigned short*)&p[i]);
	i+=2;
	cout<<" I = is this much"<<i<<endl;
	destport=ntohs(*(unsigned short*)&p[i]);
	cout<<sourceport<<" this is source port"<<endl;
	if(sourceport==7831)
	{

		
		globe=Send_forged(p,client,sourceport,destport);
		return globe;

	}
	
	else if(destport==7831)
	{
		client=true;
		globe=Send_forged(p,client,sourceport,destport);

		return globe;
	}


	return NULL;
}

 void ip_order(const unsigned char *p, int i,bool state=false)
  {

	  char num[4];
	  char ip4_addr[20];
	  in_addr adr;
	  char *a1;
	  for(int j=0,k=i;j<4;j++,k++)
	  {
		num[j]=p[k];		
	  }
	 
	  
	  unsigned int jam=0;
	  jam=*(unsigned int*)num;
	  //or
	  //memcpy(&jam,num,sizeof(int));


	  //jam =((jam>>24)&0x000000FF) | ((jam>>8)&0x0000FF00) | ((jam<<8)&0x00FF0000) | ((jam<<24)&0xFF000000);

	  adr.S_un.S_addr=jam;
	  //strcpy(ip4_addr,(inet_ntoa(adr)));
	  a1=inet_ntoa(adr);
	  strcpy(ip4_addr,a1);
	  test.open("E:\\WTF.TXT",ios::app|ios::out);
	  if(state==false)
	  {
	  test<<"source address: "<<ip4_addr<<"\n";
	  test.close();
	  i+=4;
	  ip_order(p,i,true);
	  }
      
	  
	  if(state==true)
	  {
		  test<<"destination address: "<<ip4_addr<<"\n\n";
		  i+=4;
		  test.close();

	  }

  } 

const unsigned char * IP_TCP_UDP(const unsigned char *p)
{

    int i=12;
	//unsigned char size[2]={p[i],p[++i]};  //can also convert p[i] directly to unsigned short pointer
	unsigned short saga2=ntohs(*(unsigned short*)&p[i]);
	i++;
	//unsigned short saga=*(unsigned short*)(size);
	//saga=((saga>>8)&0X00FF)|((saga<<8)&0xFF00);
	cout<<"**"<<saga2<<"**";
	//cout<<(((saga>>8)&0X00FF)|((saga<<8)*0xFF00));
	//cout<<"***"<<p[i-1]<<"***";
	if(saga2==2048)
	{
		i++;
		char abc[120];
		//test.open("E:\\WTF.TXT",ios::app|ios::out);
		//test<<"ip: 0x0800"<<"\n";		
		//sprintf(abc,"IP VERSION: %.2X \nHeader Length: %.2X (%d)\n\0",(p[i]&0X4),(p[i]&0X05),((int)(p[i]&0X5))*4);
		//test<<abc;

		//i++;
		//memset(abc,'\0',sizeof(abc));
		//sprintf(abc,"Differentiated Services Field: %.2X = %d\n\0",p[i],p[i]);
		//test<<abc;
		i+=3;
		memset(abc,'\0',sizeof(abc));
		unsigned char size1[2]={p[i],p[i-1]};
		unsigned short int kebel=*(unsigned short int*)size1;
		cout<<"this is kebel value: "<<kebel<<endl;
		if(kebel==40)
		{
			tcpcheck(p,i+17);
		}
		
		//cout<<"FAILED IN iptcp\n\n\n";
		return globe;
		
	}
	else
	{
		cout<<" FAILED in iptcp\n\n\n";
		return NULL;
	}
	
}


const unsigned char* MacAddr(const unsigned char *p)
{
	
	unsigned char abc[6];
	unsigned char abc1[120];
	

	for(int i=0;i<12;i++)
	{
		static int j=0;
		
		
		abc[j]=p[i];

		j++;
		if(i==5)
		{
			test.open("E:\\WTF.TXT",ios::app|ios::out);
			sprintf(reinterpret_cast<char*>(abc1),"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\0",abc[0],abc[1],abc[2],abc[3],abc[4],abc[5]);
			test<<std::hex<<reinterpret_cast<char*>(abc1)<<"\n";
			test.close();
			j=0;
		}

		if(i==11)
		{

			test.open("E:\\WTF.TXT",ios::app|ios::out);
			sprintf(reinterpret_cast<char*>(abc1),"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\0",abc[0],abc[1],abc[2],abc[3],abc[4],abc[5]);
			test<<std::hex<<reinterpret_cast<char*>(abc1)<<"\n";
			test.close();
			j=0;
			IP_TCP_UDP(p);
		}

	}


	return globe;
}

char abc2[2048];
int rate=0;

#define LINE_LEN 16

  int main(int argc, char **argv)
{   
	
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	u_int inum, i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

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

    /* Read the packets */
    while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
    {

		//if(repeat)
		//{
		//	pkt_data=NULL;
		//	repeat=false;
		//	continue;
		//}

        if(res == 0)
            /* Timeout elapsed */
            continue;

        /* print pkt timestamp and pkt len */
        printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);          
        
        /* Print the packet */
        for (i=1; (i < header->caplen + 1 ) ; i++)
        {
            printf("%.2x ", pkt_data[i-1]);
            if ( (i % LINE_LEN) == 0) printf("\n");
			//abc2[rate]=pkt_data[i-1];
			//rate++;
        }
        if(!MacAddr(pkt_data)==NULL)
		{
		//rate=0;
		Sleep(200);
		if (pcap_sendpacket(fp,globe ,abcd/* size */) != 0)
			{
			cout<<"*:*"<<abcd<<endl<<endl;
			
			fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
			return 1;
			}
		//exit(1);
		}
		
        printf("\n\n");     
    }

	
    if(res == -1)
    {
        fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
        return -1;
    }

	
	
    return 0;
}

