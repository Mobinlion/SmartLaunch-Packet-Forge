 

struct ethernet{

	unsigned char ka[6];
	unsigned char ka2[6];
	unsigned short ka3;

}eth,*peth;

struct ip_hdr1
	{

		unsigned char ip_verlen;
		unsigned char ip_tos;
		unsigned short ip_totallength;
		unsigned short ip_id;
		unsigned short ip_offset;
		unsigned char ip_ttl;
		unsigned char ip_protocol;
		unsigned short ip_checksum;
		unsigned int ip_src;
		unsigned int ip_dest;

	}ipv4,*pipv4;



 struct tcp_hdr
	{

		unsigned short tcp_srcport;
		unsigned short tcp_dstport;
		unsigned int tcp_sequence;
		unsigned int tcp_ack;
		unsigned short tcp_offset;
		//unsigned char tcp_flags;
		unsigned short tcp_windowsize;
		unsigned short tcp_checksum;
		unsigned short tcp_urgentpointer;
		

	}tcphdr,*ptcphdr,*tcpchecksum;


unsigned short checksum (unsigned short *buffer, int size);






struct pseudo{

	
	unsigned int ipsrc;
	unsigned int ipdest;
	unsigned short TCPDATALENGTH;
	unsigned char prot;	
	unsigned char reserved;
	
	
	


}seudo,*ppseudo;