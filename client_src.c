/*
  Copyright (c) 2015 kewl-networks

  Authors: Ruchika Verma
           Anjali Thakur
           Sowmya G Kumar
           Akash Raj
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

/*different field types*/
#define T_AAAA 28   //ipv6
#define T_A 1       //ipv4
#define T_NS 2      //nameserver
#define T_CNAME 5   //canonical name
#define T_SOA 6     //state of authority zone
#define T_PTR 12    //reverse lookup
#define T_MX 15
//#define T_ALIAS    ASK SIR 


/* function declarations */
void getHostByName(unsigned char *domainName,int queryType);
void changeToDnsFormat(unsigned char*,unsigned char*);
unsigned char* readName (unsigned char*,unsigned char*,int*);
void get_dns_servers();

char dns_servers[10][20];
int dns_server_count =0;


/*DNS structure header*/
struct DNS_HEADER
{
  unsigned short id;

  unsigned char rd:1;       //recursion desired
  unsigned char tc:1;       //truncated message
  unsigned char aa:1;       //authoritative answer
  unsigned char opcode:4;   //purpose of message
  unsigned char qr:1;       //query or response flag

  unsigned char rcode:1;    //response code
  unsigned char cd:1;       //checking disabled
  unsigned char ad:1;       //authenticated data
  unsigned char z:1;        //reserved
  unsigned char ra:1;       //recursion available

  unsigned char q_count;    //number of question entries
  unsigned char ans_count;  //number of answers entries
  unsigned char auth_count; //number of authority entries
  unsigned char add_count;  //number of resource entries
};

/* constant sized fields of query structure */
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

/* record structure */
#pragma pack(push, 1) //allocates only exact size of struct amount of memory
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

/* pointer to resource record contents */
struct RES_RECORD
{
  unsigned char *name;
  struct R_DATA *resource;
  unsigned char *rdata;
};

typedef struct
{
  unsigned char *name;
  struct QUESTION *ques;
} QUERY;


void get_dns_servers()
{
  FILE *fp;
  char line[200],*p;
  if((fp=fopen("etc/resolv.conf","r"))==NULL)
  {
    printf("Fialed opening\n");
  }

  while(fgets(line,200,fp))
  {
    if(line[0]=='#')
    {
      continue;
    }
    if(strncmp(line,"nameserver",10)==0)
    {
      p=strtok(line," ");
      p=strtok(NULL," ");
    }
  } 
  
  //strcpy(dns_servers[0],p);   //loopback
  strcpy(dns_servers[0], "8.8.8.8");
  strcpy(dns_servers[1], "8.8.4.4");
}


/*readName function to be written here */
u_char* readName(unsigned char* reader,unsigned char* buffer,int* count)
{
  unsigned char *name;
  unsigned int p=0,jumped=0,offset;
  int i , j;

  *count = 1;
  name = (unsigned char*)malloc(256);
  name[0]='\0';

  //read the names in 3www6google3com format
  while(*reader!=0)
  {
    if(*reader>=192)
    {
      offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
      reader = buffer + offset - 1;
      jumped = 1; //we have jumped to another location so counting wont go up!
    }
    else
    {
      name[p++]=*reader;
    }

    reader = reader+1;

    if(jumped==0)
    {
      *count = *count + 1; //if we havent jumped to another location then we can count up
    }
  }

  name[p]='\0'; //string complete
  if(jumped==1)
  {
    *count = *count + 1; //number of steps we actually moved forward in the packet
  }

  //now convert 3www6google3com0 to www.google.com
  for(i=0;i<(int)strlen((const char*)name);i++) 
  {
    p=name[i];
    for(j=0;j<(int)p;j++) 
    {
      name[i]=name[i+1];
      i=i+1;
    }
    name[i]='.';
  }

  name[i-1]='\0'; //remove the last dot

  return name;
}


void changeToDnsFormat(unsigned char* dns,unsigned char* host) 
{
  int lock = 0 , i;
  strcat((char*)host,".");
   
  for(i = 0 ; i < strlen((char*)host) ; i++) 
  {
    if(host[i]=='.') 
    {
      *dns++ = i-lock;
      for(;lock<i;lock++) 
      {
        *dns++=host[lock];
      }

      lock++;
    }
  }
  *dns++='\0';
}


void changeIPtoDnsFormat(unsigned char* dns,unsigned char* hostip)
{
  int i, iplen;

  unsigned char revip[100];

  iplen = strlen(hostip);

  for(i=0; i<iplen; ++i)
  {
      revip[i] = hostip[iplen-i-1];
  }
  revip[i] = '\0';

  strcat(revip, ".inet-addr.arpa");
  revip[i+15] = '\0';

  changeToDnsFormat(dns, revip);
}


void getHostByName(unsigned char *host,int query_type)
{
  int val;
  
  printf("Iterative or Recursive query ?0:1");
  scanf("%d",&val);
  
  unsigned char buf[65536],*qname,*reader;
  int i,j,stop,s;
  struct sockaddr_in a;
  struct RES_RECORD answers[20],auth[20],addit[20];
  struct sockaddr_in dest;
  struct DNS_HEADER *dns=NULL;
  struct QUESTION *qinfo = NULL;
  
  printf("Making the socket ....... \n");
  
  s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); //socket made
  
  dest.sin_family=AF_INET;
  dest.sin_port=htons(53);
  dest.sin_addr.s_addr=inet_addr(dns_servers[0]);

  dns=(struct DNS_HEADER *)&buf;
  dns->id=(unsigned short) htons(getpid());
  dns->qr=0;
  dns->opcode=0;
  dns->aa=0;
  dns->tc=0;
  dns->rd=val;
  dns->ra=0;
  dns->z=0;
  dns->ad=0;
  dns->cd=0;
  dns->rcode=0;
  dns->q_count=htons(1);
  dns->ans_count=0;
  dns->auth_count=0;
  dns->add_count=0;

  qname=(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

  if(query_type==T_PTR)
  { 
    changeIPtoDnsFormat(qname,host);
  }
  else  
  {
    changeToDnsFormat(qname,host);
  }

  qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
  qinfo->qtype = htons( query_type );
  qinfo->qclass = htons(1);

  printf("Packet being sent ...... ");  
  
  if(sendto (s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest))<0)
  {
    perror("sento failed ");
  } 
  printf("Done");


  /*receiving the answer */
  i=sizeof dest;
  printf("Answer is being Received..... ");
  if(recvfrom(s,(char*)buf,65536,0,(struct sockaddr*)&dest,(socklen_t*)&i)<0)
  {
    perror("recvfrom failed");
  }

  printf("Done");

  dns=(struct DNS_HEADER*) buf;

  reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

  printf("\n response contian:");
  printf("\n %d Questions ", ntohs(dns->q_count));
  printf("\n %d Answers.", ntohs(dns->ans_count));
  printf("\n %d authoritative servers.", ntohs(dns->auth_count));
  printf("\n %d additional records.\n" , ntohs(dns->add_count));
  
  //read answers
  stop = 0;

  for(i=0; i<ntohs(dns->ans_count); ++i)
  {
    answers[i].name = readName(reader, buf, &stop);
    reader = reader + stop;
    
    answers[i].resource = (struct R_DATA*)(reader);
    reader = reader + sizeof(struct R_DATA);

    if(ntohs(answers[i].resource->type)==1)
    {
      answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

      for(j=0; j<ntohs(answers[i].resource->data_len); ++j)
      {
        answers[i].rdata[j] = reader[j];
      }

      answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
      reader += ntohs(answers[i].resource-> data_len);
    }
    else
    {
      answers[i].rdata = readName(reader, buf, &stop);
      reader +=stop;
    }
  }
  
  //authorities
  for( i=0; i<ntohs(dns->auth_count); ++i)
  {
    auth[i].name = readName(reader, buf, &stop);
    reader += stop;

    auth[i].resource = (struct R_DATA*)(reader);
    reader += sizeof(struct R_DATA);

    auth[i].rdata = readName(reader, buf, &stop);
    reader += stop;
  }


  //for additional
  for(i =0; i<ntohs(dns->add_count); ++i)
  {
    addit[i].name = readName(reader, buf, &stop);
    reader += stop;

    addit[i].resource = (struct R_DATA*)(reader);
    reader += sizeof(struct R_DATA);

    if(ntohs(addit[i].resource->type)==1)
    {
      addit[i].rdata = (unsigned char*) malloc(ntohs(addit[i].resource->data_len));
      for(j=0; j<ntohs(addit[i].resource->data_len); ++j)
        addit[i].rdata[j] = reader[j];

      addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
      reader += ntohs(addit[i].resource -> data_len);
    }
    else
    {
      addit[i].rdata = readName(reader, buf, &stop);
      reader +=stop;
    }   
  }

  //print answers
  printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
  for(i=0 ; i < ntohs(dns->ans_count) ; i++)
  {
    printf("Name : %s ",answers[i].name);

    if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
    {
      long *p;
      p=(long*)answers[i].rdata;
      a.sin_addr.s_addr=(*p); //working without ntohl
      printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
    }
     
    if(ntohs(answers[i].resource->type)==5) 
    {
      //Canonical name for an alias
      printf("has alias name : %s",answers[i].rdata);
    }

    printf("\n");
  }
 
  //print authorities
  printf("\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
  
  for( i=0 ; i < ntohs(dns->auth_count) ; i++)
  {
    printf("Name : %s ",auth[i].name);
    if(ntohs(auth[i].resource->type)==2)
    {
      printf("has nameserver : %s",auth[i].rdata);
    }
    printf("\n");
  }

  //print additional resource records
  printf("\nAdditional Records : %d \n" , ntohs(dns->add_count) );
  for(i=0; i < ntohs(dns->add_count) ; i++)
  {
    printf("Name : %s ",addit[i].name);
    if(ntohs(addit[i].resource->type)==1)
    {
      long *p;
      p=(long*)addit[i].rdata;
      a.sin_addr.s_addr=(*p);
      printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
    }
    printf("\n");
  }

  return;
}


void ipv4()
{
  unsigned char hostname[10][100];
  
  printf("Enter the Hostname : ");
  scanf("%s",hostname[0]);
  getHostByName(hostname[0],T_A);
  getHostByName(hostname[0],T_AAAA);
  getHostByName(hostname[0],T_MX);
  getHostByName(hostname[0],T_NS);
  getHostByName(hostname[0],T_CNAME);
  getHostByName(hostname[0],T_SOA);
}


void rev_lookup()
{
  unsigned char rev_hostname[10][100];
  printf("Enter the IP address : ");
  scanf("%s",rev_hostname[0]);
  getHostByName(rev_hostname[0],T_PTR);
}


int main(int argc,char *argv[])
{
  //make a menu
  int choice;

  get_dns_servers();

  printf("enter 1 for direct lookup and 2 for reverse lookup\n");
  scanf("%d", &choice);

  switch(choice)
  {
    case 1: ipv4();
             break;
    case 2: rev_lookup();
             break;
    deafult:exit(0);
  }

  return 0;
}




