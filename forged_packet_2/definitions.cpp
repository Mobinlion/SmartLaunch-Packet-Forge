#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 
#endif
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "winsock2.h"
#include "Mswsock.h"

#include "declare.h"
#include "ws2tcpip.h"
#include "iostream"
using namespace std;
//#include "Ws2def.h"

int abcd=0;   //external global int, see main.cpp for extern keyword
char buf[2048];

USHORT checksumTCP(USHORT *buffer, int size,int sizeof_data)
{
 unsigned long cksum=0;

	
    
	/**((unsigned int*)&buffer[size])=srcip;
	size+=sizeof(srcip);
	*((unsigned int*)&buffer[size])=dstip;	
	size+=sizeof(srcip);
	*((unsigned char*)&buffer[size])=protocol;
    size+=sizeof(protocol);
    *(&buffer[size])=tcpDataLength;
	size+=sizeof(tcpDataLength);*/
	
		//(char*)(buffer++);
	cout<<endl<<std::hex<<*buffer<<endl<<endl<<"this is one\n";
	
	while (sizeof_data>1)
	{

		printf("data: %.4X    ",*buffer); 
        cksum += ntohs(*buffer++);
        sizeof_data  -= sizeof(USHORT);

	}
	 if (sizeof_data)
    {
		printf("%.4X    ",*buffer); 
        cksum += ntohs((*(UCHAR*)buffer));   
    }

    while (size > 1)
    {
		printf("%.4X    ",*buffer); 
        cksum += *buffer++;
        size  -= sizeof(USHORT);   
    }
    if (size)
    {
		printf("%.4X    ",*buffer); 
        cksum += *(UCHAR*)buffer;   
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16); 

	std::cout<<"original: "<<(~cksum)<<endl<<std::hex<<"host order: "<<((USHORT)(~cksum))<<endl;
	std::cout<<"network byte order: "<<std::hex<<htons((USHORT)(~cksum))<<endl;
	
    return (USHORT)(~cksum);
}


USHORT checksum(USHORT *buffer, int size)
{
 unsigned long cksum=0;

 
 cout<<"initial SIZE: "<<size<<endl;
		//(char*)(buffer++);
	//cout<<endl<<std::hex<<*buffer<<endl<<endl<<"this is one";
  

    while (size > 1)
    {
		printf("%.4X    ",*buffer); 
        cksum += *buffer++;
        size  -= sizeof(USHORT);   
    }
    if (size)
    {
		printf("%.4X    ",*buffer);
        cksum += *(UCHAR*)buffer;   
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16); 

	//std::cout<<"original: "<<(~cksum)<<endl<<std::hex<<"host order: "<<((USHORT)(~cksum))<<endl;
	//std::cout<<"network byte order: "<<std::hex<<htons((USHORT)(~cksum))<<endl;
	cout<<"end SIZE: "<<size<<endl;
    return (USHORT)(~cksum);
}



 const unsigned char* Send_forged()
{

	//SOCKET sock;
	
	//har buf[2048]; //gives error that buffer is out of scope cause its local
	unsigned char *data=NULL;
	WSADATA wsadata;

	char kalampolo[]="hello, this is captain Johlikkeirokdjg";
	unsigned char kalampolo2[256];	
	
	int size3=sizeof(kalampolo);
	memcpy(kalampolo2,kalampolo,sizeof(kalampolo));
	for(int i=0 ; i < size3%2 ; i++)
    {
        //printf("pad one byte\n");
        kalampolo2[size3] = 0;
        size3++;
		//chksumlen++;
    }


	if((WSAStartup(MAKEWORD(2,2),&wsadata))!=0)
	{
		//cout<<"error is in WSAstartup";
			return NULL;

	}


	peth=(ethernet*)buf;
	peth->ka[0]=0X00;
	peth->ka[1]=0X1F;
	peth->ka[2]=0XD0;
	peth->ka[3]=0XAC;
	peth->ka[4]=0XC3;
	peth->ka[5]=0XB4;

	peth->ka2[0]=0X00;
	peth->ka2[1]=0X1F;
	peth->ka2[2]=0XD0;
	peth->ka2[3]=0XAC;
	peth->ka2[4]=0XC3;
	peth->ka2[5]=0XB4;

	peth->ka3=0X08;




	pipv4=NULL;
	ptcphdr=NULL;
	USHORT sourceport=100,destport=1000;
	int payload=512;//,optval;
//	SOCKADDR_STORAGE dest;

	pipv4=(ip_hdr1*)&buf[sizeof(eth)];
	pipv4->ip_verlen=(4<<4)|(sizeof(ipv4)/sizeof(ULONG));
	pipv4->ip_tos=0;
	pipv4->ip_totallength=htons(sizeof(ipv4)+sizeof(tcphdr)+sizeof(kalampolo));  //must put it dynamically
	pipv4->ip_id=0;
	pipv4->ip_offset=0;
	pipv4->ip_ttl=224; //TTL is 8
	pipv4->ip_protocol=IPPROTO_TCP;
	pipv4->ip_checksum=0; //will calculate later
	pipv4->ip_src=inet_addr("192.168.1.2");//must put it dynamically
	pipv4->ip_dest=inet_addr("192.168.1.2"); //must put it dynamically

	pipv4->ip_checksum=checksum((USHORT*)pipv4,sizeof(ipv4));


	ptcphdr=(tcp_hdr*)&buf[sizeof(ip_hdr1)+sizeof(ethernet)];
	ptcphdr->tcp_srcport=htons(18372); //must put dynamically
	ptcphdr->tcp_dstport=htons(5555); //must put dynamically
	ptcphdr->tcp_sequence=htonl(0x4B151C85);
	ptcphdr->tcp_ack=htonl(0xEB0B6BFF);
	ptcphdr->tcp_offset=htons(0x5<<12|(0x04));//0x04 for rst
	//ptcphdr->tcp_flags=0x01;
	ptcphdr->tcp_windowsize=htons(2048);
	ptcphdr->tcp_checksum=0;  //dynamically
	ptcphdr->tcp_urgentpointer=0; //if urgent pointer flag is set

	
	
	//payload initialization

	data=(unsigned char*)&buf[sizeof(ip_hdr1) + sizeof(tcp_hdr)+sizeof(ethernet)];
	

	
	memcpy(data,kalampolo2,size3);
	


	ppseudo=(pseudo*)&buf[sizeof(ip_hdr1) + sizeof(tcp_hdr)+sizeof(ethernet)+size3];
	ppseudo->TCPDATALENGTH=ntohs(pipv4->ip_totallength)-20;
	cout<<"THIS IS TOTALLENGTH<*>*<*>*<: "<<ntohs(pipv4->ip_totallength)-20<<endl;
	ppseudo->prot=0X06;
	ppseudo->reserved=0;

	cout<<ppseudo->prot<<"WTF: : : : :";
	
	
	ppseudo->ipdest=ntohl(pipv4->ip_dest);
	ppseudo->ipsrc=ntohl(pipv4->ip_src);

	tcpchecksum=(tcp_hdr*)&buf[sizeof(ethernet)+sizeof(ip_hdr1)+sizeof(tcp_hdr)+size3+sizeof(seudo)];
	tcpchecksum->tcp_srcport=ntohs(ptcphdr->tcp_srcport);
	tcpchecksum->tcp_dstport=ntohs(ptcphdr->tcp_dstport);
	tcpchecksum->tcp_sequence=ntohl(ptcphdr->tcp_sequence);
	tcpchecksum->tcp_ack=ntohl(ptcphdr->tcp_ack);
	tcpchecksum->tcp_offset=ntohs(ptcphdr->tcp_offset);
	tcpchecksum->tcp_windowsize=ntohs(ptcphdr->tcp_windowsize);
	tcpchecksum->tcp_checksum=0;
	tcpchecksum->tcp_urgentpointer=ntohs(ptcphdr->tcp_urgentpointer);
	

	/*unsigned int *intel=(unsigned int*)&buf[sizeof(ip_hdr1) + sizeof(tcp_hdr)+sizeof(ethernet)];
	*intel=inet_addr("0.0.0.0");
	unsigned int *intel1=(unsigned int*)&buf[sizeof(ip_hdr1) + sizeof(tcp_hdr)+sizeof(ethernet)+4];
	*intel=inet_addr("0.0.0.0");
	unsigned char *prot=(unsigned char*)&buf[sizeof(ip_hdr1) + sizeof(tcp_hdr)+sizeof(ethernet)+8];;
	*prot=0x06;
	unsigned char *reserved=(unsigned char*)&buf[sizeof(ip_hdr1) + sizeof(tcp_hdr)+sizeof(ethernet)+9];;
	*reserved=0X00;
	unsigned short *TCPDATALENGTH=(unsigned short*)&buf[sizeof(ip_hdr1) + sizeof(tcp_hdr)+sizeof(ethernet)+10];
	*TCPDATALENGTH=0x14;*/



	int chksumlen=0;
	chksumlen=sizeof(tcp_hdr)+12;

	int counter=sizeof(ip_hdr1) + sizeof(tcp_hdr)+sizeof(ethernet)+sizeof(seudo)+sizeof(tcp_hdr);

	int sizeof_seudo=sizeof(seudo)+sizeof(tcphdr);
	int sizeof_data=size3;
	int size2=sizeof(pseudo)+sizeof(tcp_hdr)+sizeof(tcp_hdr);
	/*for(int i=0 ; i < size2%2 ; i++)
    {
        //printf("pad one byte\n");
        buf[counter] = 0;
        counter++;
        chksumlen++;
    }
*/
	
	cout<<counter<<endl<<"checksumlength"<<chksumlen<<endl;
	//cout<<sizeof(pseudo);

	ptcphdr->tcp_checksum=htons(checksumTCP((USHORT*)data,sizeof_seudo,sizeof_data));
	cout<<endl<<endl<<std::hex<<"checksum: "<<ptcphdr->tcp_checksum<<endl<<endl<<"&**^";
	
	//cout<<std::dec<<endl<<ntohs(pipv4->ip_totallength)-20;
	//size_forge((sizeof(ipv4)+sizeof(tcphdr)+sizeof(kalampolo)+sizeof(eth)));
	//size1.a=(sizeof(ipv4)+sizeof(tcphdr)+sizeof(kalampolo)+sizeof(eth));
	//size1.p=buf;

	int wtf=(sizeof(ethernet)+sizeof(ipv4)+sizeof(tcphdr)+sizeof(kalampolo));
	cout<<std::dec<<endl<<wtf<<endl;
	
	abcd=wtf;
	return (const unsigned char*)buf;

	//sock=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
	//if(sock==-1)
	//{
		//cout<<"SOCKET FAILED TOO";
		//cout<<endl<<GetLastError();
	//}
	/*optval=1;
	if(setsockopt(sock,IPPROTO_IP,IP_HDRINCL, (char*)&optval, sizeof(optval))==-1)
	{
		//std::cout<<"SETSOCKOPT FAILED!";
		//cout<<endl<<GetLastError();
		
	}

	((SOCKADDR_IN*)&dest)->sin_family=AF_INET;
	((SOCKADDR_IN*)&dest)->sin_port=htons(5555);
	((SOCKADDR_IN*)&dest)->sin_addr.S_un.S_addr=inet_addr("192.168.1.4");

	if(sendto(sock,buf,(sizeof(ipv4)+sizeof(tcphdr)+sizeof(kalampolo)),0,(SOCKADDR*)&dest,sizeof(dest))==-1)
	{
		//cout<<"sendto also failed";
		//cout<<endl<<GetLastError();
	}
*/


}









