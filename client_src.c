/*----------------------------------------------------------------------------*/
/*                                                                            */
/*   Copyright (c) 2015 kewl-networks                                         */
/*   All rights reserved.                                                     */
/*                                                                            */
/*   Authors:  Ruchika Verma                                                  */
/*             Sowmya G Kumar                                                 */
/*             Anjali Thakur                                                  */
/*             Akash Raj K N                                                  */
/*                                                                            */
/*----------------------------------------------------------------------------*/
 
#include <stdio.h> 
#include <string.h>   
#include <stdlib.h>   
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <unistd.h>    


unsigned char user_hostname[10][100];
char dns_servers[10][20];
int dns_server_count = 0;


#define T_AAAA 28                      // ipv6
#define T_A 1                          // ipv4 address
#define T_NS 2                         // nameserver
#define T_CNAME 5                      // canonical name
#define T_SOA 6                        // start of authority zone
#define T_PTR 12                       // domain name pointer 
#define T_MX 15                        // mail server

 
/* function declarations */
void directLookup();
void reverseLookup();
void soaLookup();
void ipv6Lookup();
void mxLookup();
void nsLookup();
void ngethostbyname (unsigned char* , int);
void changetoDnsFormat (unsigned char*,unsigned char*);
void changeIPtoDnsFormat(unsigned char*, unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);
void get_dns_servers();
void rev_lookup();
void changeIPtoDnsFormat(unsigned char *, unsigned char *);


/* DNS header structure */
struct DNS_HEADER
{
  unsigned short id;                   // identification number
 
  unsigned char rd :1;                 // recursion desired
  unsigned char tc :1;                 // truncated message
  unsigned char aa :1;                 // authoritive answer
  unsigned char opcode :4;             // purpose of message
  unsigned char qr :1;                 // query/response flag

  unsigned char rcode :4;              // response code
  unsigned char cd :1;                 // checking disabled
  unsigned char ad :1;                 // authenticated data
  unsigned char z :1;                  // reserved
  unsigned char ra :1;                 // recursion available

  unsigned short q_count;              // number of question entries
  unsigned short ans_count;            // number of answer entries
  unsigned short auth_count;           // number of authority entries
  unsigned short add_count;            // number of resource entries
};
 

/* question structure */
struct QUESTION
{
  unsigned short qtype;
  unsigned short qclass;
};
 
/* resource record structure */
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 

/* Pointers to resource record contents */
struct RES_RECORD
{
  unsigned char *name;
  struct R_DATA *resource;
  unsigned char *rdata;
};
 

/* query structure */
typedef struct
{
  unsigned char *name;
  struct QUESTION *ques;
} QUERY;
 

int main( int argc , char *argv[])
{
  unsigned char hostname[100];
  int choice;

  //Get the DNS servers from the resolv.conf file
  get_dns_servers();

  printf("enter \n1 for direct lookup\n2 for reverse lookup\n3 for start of authority\n4 for ipv6 address\n");
  printf("5 for MX record\n6 for NS record\n");
  printf("choice = ");

  scanf("%d", &choice);

  switch(choice)
  {
    case 1: directLookup();
            break;

    case 2: reverseLookup();
            break;

    case 3: soaLookup();
            break;

    case 4: ipv6Lookup();
            break;

    case 5: mxLookup();
            break;

    case 6: nsLookup();
            break;

    default: printf("choice entered is invalid\n");
  }

  return 0;
}


void directLookup()
{
  printf("enter the hostname: ");
  scanf("%s", user_hostname[0]);

  ngethostbyname(user_hostname[0], T_A);
}


void reverseLookup()
{
  printf("Enter the IP address : ");
  scanf("%s",user_hostname[0]);
  
  ngethostbyname(user_hostname[0],T_PTR);
}


void soaLookup()
{
  printf("enter the hostname: ");
  scanf("%s", user_hostname[0]);

  ngethostbyname(user_hostname[0], T_SOA);
}


void ipv6Lookup()
{
  printf("enter the hostname: ");
  scanf("%s", user_hostname[0]);

  ngethostbyname(user_hostname[0], T_AAAA); 
}


void mxLookup()
{
  printf("enter the hostname: ");
  scanf("%s", user_hostname[0]);

  ngethostbyname(user_hostname[0], T_MX);
}


void nsLookup()
{
  printf("enter the hostname: ");
  scanf("%s", user_hostname[0]);

  ngethostbyname(user_hostname[0], T_NS);
}


/* sends a packet and performs a dns query */
void ngethostbyname(unsigned char *host , int query_type)
{
  unsigned char buf[65536],*qname,*reader;
  int i , j , stop , s;

  struct sockaddr_in a;
  struct sockaddr_in6 b;
  
  struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
  struct sockaddr_in dest, dest6;

  struct DNS_HEADER *dns = NULL;
  struct QUESTION *qinfo = NULL;

  printf("Resolving %s" , host);

  s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);      //UDP packet for DNS queries

  dest.sin_family = AF_INET;
  dest.sin_port = htons(53);
  dest.sin_addr.s_addr = inet_addr(dns_servers[0]);    //dns servers

  //Set the DNS structure to standard queries
  dns = (struct DNS_HEADER *)&buf;

  dns->id = (unsigned short) htons(getpid());
  dns->qr = 0;                                         //This is a query
  dns->opcode = 0;                                     //This is a standard query
  dns->aa = 0;                                         //Not Authoritative
  dns->tc = 0;                                         //This message is not truncated
  dns->rd = 1;                                         //Recursion Desired
  dns->ra = 0;                                         //Recursion not available
  dns->z = 0;
  dns->ad = 0;
  dns->cd = 0;
  dns->rcode = 0;
  dns->q_count = htons(1);                             //we have only 1 question
  dns->ans_count = 0;
  dns->auth_count = 0;
  dns->add_count = 0;

  //point to the query portion
  qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

  if(query_type==T_PTR)
  {
    changeIPtoDnsFormat(qname, host);
  }
  else
  {
    changetoDnsFormat(qname , host);
  }

  qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

  qinfo->qtype = htons( query_type );                  // type of the query , A , MX , CNAME , NS etc
  qinfo->qclass = htons(1);                            // 1 denotes internet

  printf("\nSending Packet...");
  if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
  {
    perror("sendto failed");
  }
  printf("Done");

  //Receive the answer
  i = sizeof dest;
  printf("\nReceiving answer...");
  if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
  {
    perror("recvfrom failed");
  }
  printf("Done");

  dns = (struct DNS_HEADER*) buf;

  if( ntohs(dns->tc) == 0)
  {

    //move ahead of the dns header and the query field
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

    printf("\nThe response contains : ");
    printf("\n %d Questions.",ntohs(dns->q_count));
    printf("\n %d Answers.",ntohs(dns->ans_count));
    printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
    printf("\n %d Additional records.\n\n",ntohs(dns->add_count));

    //Start reading answers
    stop=0;

    char str[100],*temp,word[50];
    int stridx=0,numdots=0,tempc=0;
    j=2;

    for(i=0;i<ntohs(dns->ans_count);i++)
    {
      answers[i].name=ReadName(reader,buf,&stop);

      if(i==0)
      {
        for(temp=answers[i].name;*temp!='.';temp++)
        {
            word[tempc++]=*temp;
        }
        word[tempc]='\0';
      }

      reader = reader + stop;

      answers[i].resource = (struct R_DATA*)(reader);
      reader = reader + sizeof(struct R_DATA);

      if(ntohs(answers[i].resource->type) == 1)                      //if its an ipv4 address
      {
        answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

        for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
        {
          answers[i].rdata[j]=reader[j];
        }

        answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

        reader = reader + ntohs(answers[i].resource->data_len);
      }
      else if(ntohs(answers[i].resource->type)==T_MX)
      {
        int count,k;
        answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
        j=2;
        while(reader[j]!=192)
        {
          count=reader[j];
          j++;
          numdots++;
          for(k=0;k<count;k++)
          {
            printf("%c",reader[j+k]);
            if(i==0)
              str[stridx++]=reader[j+k];
          }
            
          if(reader[j]==192)
              break;
          if(i==0)
              str[stridx++]='.';

          printf(".");
          j+=count;
        }
        str[stridx]='\0';
        
        if(numdots==0)
        {
          char *pch=strchr(str,'.');
          printf("%s",pch+1);
        }
        else if(i!=0)
        {
          printf("%s",str+(j-3+numdots));
        }
        if(strstr(str,word)==NULL)
        {
          printf("%s",answers[i].name);
        }
        
        printf("\n");
        
        numdots=0;
       
        answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

        reader = reader + ntohs(answers[i].resource->data_len);
      }
      else if(ntohs(answers[i].resource->type) == 28) //if its an ipv6 address
      {
        answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
   //     printf("length is %d\n",ntohs(answers[i].resource->data_len) );
        for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
        {
          answers[i].rdata[j]=reader[j];     
        }
        
        answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
     //   printf("%s\n",answers[i].rdata);
        reader = reader + ntohs(answers[i].resource->data_len);
      }
      else
      {
        answers[i].rdata = ReadName(reader,buf,&stop);
        reader = reader + stop;
      }
    }

    //read authorities
    for(i=0;i<ntohs(dns->auth_count);i++)
    {
      auth[i].name=ReadName(reader,buf,&stop);
      reader+=stop;

      auth[i].resource=(struct R_DATA*)(reader);
      reader+=sizeof(struct R_DATA);

      auth[i].rdata=ReadName(reader,buf,&stop);
      reader+=stop;
    }

    //read additional
    for(i=0;i<ntohs(dns->add_count);i++)
    {
      addit[i].name=ReadName(reader,buf,&stop);
      reader+=stop;

      addit[i].resource=(struct R_DATA*)(reader);
      reader+=sizeof(struct R_DATA);

      if(ntohs(addit[i].resource->type)==1)
      {
        addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
        for(j=0;j<ntohs(addit[i].resource->data_len);j++)
        addit[i].rdata[j]=reader[j];

        addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
        reader+=ntohs(addit[i].resource->data_len);
      }
      else
      {
        addit[i].rdata=ReadName(reader,buf,&stop);
        reader+=stop;
      }
    }

    //print answers
    printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
    for(i=0 ; i < ntohs(dns->ans_count) ; i++)
    {
      if(ntohs(answers[i].resource->type)==T_MX)
      {
        break; //answers already printed for T_MX
      }

      printf("Name : %s ",answers[i].name);

      if( ntohs(answers[i].resource->type) == T_A)                          //IPv4 address
      {
        long *p;
        p=(long*)answers[i].rdata;
        a.sin_addr.s_addr=(*p);                                             //working without ntohl
        printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
      }

      if(ntohs(answers[i].resource->type)==T_PTR)
      {
        printf("has the domain name : %s\n", answers[i].rdata);
      }

      if(ntohs(answers[i].resource->type)==T_CNAME) 
      {
        printf("has alias : %s",answers[i].rdata);
      }

      if(ntohs(answers[i].resource->type)==T_SOA)
      {
        printf("\nstart of authority : %s\n", answers[i].rdata );
      }

      if( ntohs(answers[i].resource->type) == T_AAAA) //IPv6 address
      {
        printf("has the ipv6 address = ");
        int j,k;
        for(j=0,k=1 ; j<ntohs(answers[i].resource->data_len) ; j+=2,k+=2)
        {
          if(answers[i].rdata[j]==0 && answers[i].rdata[k]==0 && k!=16)
          {
            printf(":");
            continue;
          }
          if(answers[i].rdata[j]!=0)
            printf("%x",answers[i].rdata[j]);

          if(answers[i].rdata[j]!=0 && answers[i].rdata[k]<=15)
          {
            printf("0");
          }
          printf("%x",answers[i].rdata[k]);
          
          if(k!=15)
            printf(":");
        } 
      }

      if(ntohs(answers[i].resource->type)==T_NS)
      {
        printf(" has the nameserver %s\n",answers[i].rdata);
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
  }//end of if construct
  else //size greater than 512 bytes-- establish a TCP connection
  {
    printf("UDP connection cannot handle this query-Establish a TCP connection\n");

    int qw;

    struct timeval qv;
    qv.tv_sec = 13;
    qv.tv_usec = 0;

    if( (qw = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0 )
    {
      perror("socket not created");
    }

    setsockopt(qw, SOL_SOCKET, SO_RCVTIMEO, &qv, sizeof(qv));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_servers[0]);

    dns = (struct DNS_HEADER *)&buf;
 
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0;                  //This is a query
    dns->opcode = 0;              //This is a standard query
    dns->aa = 0;                  //Not Authoritative
    dns->tc = 0;                  //This message is not truncated
    dns->rd = 1;                  //Recursion Desired
    dns->ra = 0;                  //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1);      //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
 
    changetoDnsFormat(qname , host);
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; 
 
    qinfo->qtype = htons( query_type ); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); 

    if((connect(qw,(struct sockaddr *)&dest,sizeof(dest)))<0)
    {
      //fprintf(debug,"%s\n","Connect Error");
      perror("Connect Error");
    }
    else 
      printf("connection successful");
 
    printf("\nSending Packet...");
    //send(int s, const void *buf, size_t len, int flags);
    
    if( send(qw,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0) < 0)
    {   
      //fprintf(debug,"%s\n","sendto failed");
      perror("sendto failed");
    }

    printf("Done");
     
    //Receive the answer
    i = sizeof dest;
    printf("\nReceiving answer...");

    if(recv (qw,(char*)buf , 65536 , 0) < 0)
    {
      //fprintf(debug,"%s\n","recvfrom failed");
      perror("recvfrom failed");
    }

    printf("Done");
 
    dns = (struct DNS_HEADER*) buf;

    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
 
    printf("\nThe response contains : ");
    printf("\n %d Questions.",ntohs(dns->q_count));
    printf("\n %d Answers.",ntohs(dns->ans_count));
    printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
    printf("\n %d Additional records.\n\n",ntohs(dns->add_count));

        //Start reading answers
    stop=0;

    char str[100],*temp,word[50];
    int stridx=0,numdots=0,tempc=0;
    j=2;

    for(i=0;i<ntohs(dns->ans_count);i++)
    {
      answers[i].name=ReadName(reader,buf,&stop);

      if(i==0)
      {
        for(temp=answers[i].name;*temp!='.';temp++)
        {
            word[tempc++]=*temp;
        }
        word[tempc]='\0';
      }

      reader = reader + stop;

      answers[i].resource = (struct R_DATA*)(reader);
      reader = reader + sizeof(struct R_DATA);

      if(ntohs(answers[i].resource->type) == 1)                      //if its an ipv4 address
      {
        answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

        for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
        {
          answers[i].rdata[j]=reader[j];
        }

        answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

        reader = reader + ntohs(answers[i].resource->data_len);
      }
      else if(ntohs(answers[i].resource->type)==T_MX)
      {
        int count,k;
        answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
        j=2;
        while(reader[j]!=192)
        {
          count=reader[j];
          j++;
          numdots++;
          for(k=0;k<count;k++)
          {
            printf("%c",reader[j+k]);
            if(i==0)
              str[stridx++]=reader[j+k];
          }
            
          if(reader[j]==192)
              break;
          if(i==0)
              str[stridx++]='.';

          printf(".");
          j+=count;
        }
        str[stridx]='\0';
        
        if(numdots==0)
        {
          char *pch=strchr(str,'.');
          printf("%s",pch+1);
        }
        else if(i!=0)
        {
          printf("%s",str+(j-3+numdots));
        }
        if(strstr(str,word)==NULL)
        {
          printf("%s",answers[i].name);
        }
        
        printf("\n");
        
        numdots=0;
       
        answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

        reader = reader + ntohs(answers[i].resource->data_len);
      }
      else if(ntohs(answers[i].resource->type) == 28) //if its an ipv6 address
      {
        answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
   //     printf("length is %d\n",ntohs(answers[i].resource->data_len) );
        for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
        {
          answers[i].rdata[j]=reader[j];     
        }
        
        answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
     //   printf("%s\n",answers[i].rdata);
        reader = reader + ntohs(answers[i].resource->data_len);
      }
      else
      {
        answers[i].rdata = ReadName(reader,buf,&stop);
        reader = reader + stop;
      }
    }

    //read authorities
    for(i=0;i<ntohs(dns->auth_count);i++)
    {
      auth[i].name=ReadName(reader,buf,&stop);
      reader+=stop;

      auth[i].resource=(struct R_DATA*)(reader);
      reader+=sizeof(struct R_DATA);

      auth[i].rdata=ReadName(reader,buf,&stop);
      reader+=stop;
    }

    //read additional
    for(i=0;i<ntohs(dns->add_count);i++)
    {
      addit[i].name=ReadName(reader,buf,&stop);
      reader+=stop;

      addit[i].resource=(struct R_DATA*)(reader);
      reader+=sizeof(struct R_DATA);

      if(ntohs(addit[i].resource->type)==1)
      {
        addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
        for(j=0;j<ntohs(addit[i].resource->data_len);j++)
        addit[i].rdata[j]=reader[j];

        addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
        reader+=ntohs(addit[i].resource->data_len);
      }
      else
      {
        addit[i].rdata=ReadName(reader,buf,&stop);
        reader+=stop;
      }
    }

    //print answers
    printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
    for(i=0 ; i < ntohs(dns->ans_count) ; i++)
    {
      if(ntohs(answers[i].resource->type)==T_MX)
      {
        break; //answers already printed for T_MX
      }

      printf("Name : %s ",answers[i].name);

      if( ntohs(answers[i].resource->type) == T_A)                          //IPv4 address
      {
        long *p;
        p=(long*)answers[i].rdata;
        a.sin_addr.s_addr=(*p);                                             //working without ntohl
        printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
      }

      if(ntohs(answers[i].resource->type)==T_PTR)
      {
        printf("has the domain name : %s\n", answers[i].rdata);
      }

      if(ntohs(answers[i].resource->type)==T_CNAME) 
      {
        printf("has alias : %s",answers[i].rdata);
      }

      if(ntohs(answers[i].resource->type)==T_SOA)
      {
        printf("\nstart of authority : %s\n", answers[i].rdata );
      }

      if( ntohs(answers[i].resource->type) == T_AAAA) //IPv6 address
      {
        printf("has the ipv6 address = ");
        int j,k;
        for(j=0,k=1 ; j<ntohs(answers[i].resource->data_len) ; j+=2,k+=2)
        {
          if(answers[i].rdata[j]==0 && answers[i].rdata[k]==0 && k!=16)
          {
            printf(":");
            continue;
          }
          if(answers[i].rdata[j]!=0)
            printf("%x",answers[i].rdata[j]);

          if(answers[i].rdata[j]!=0 && answers[i].rdata[k]<=15)
          {
            printf("0");
          }
          printf("%x",answers[i].rdata[k]);
          
          if(k!=15)
            printf(":");
        } 
      }

      if(ntohs(answers[i].resource->type)==T_NS)
      {
        printf(" has the nameserver %s\n",answers[i].rdata);
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

  }

  
  return;
}
 

/* read the names in compressed form (3www6google3com0) and convert to readable form (www.google.com) */
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
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
      offset = (*reader)*256 + *(reader+1) - 49152;                //49152 = 11000000 00000000
      reader = buffer + offset - 1;

      jumped = 1;                                                  //we have jumped to another location so counting wont go up!
    }
    else
    {
      name[p++]=*reader;
    }

    reader = reader+1;

    if(jumped==0)
    {
      *count = *count + 1;                                         //if we havent jumped to another location then we can count up
    }
  }

  name[p]='\0';                                                    //string complete
  if(jumped==1)
  {
    *count = *count + 1;                                           //number of steps we actually moved forward in the packet
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
  name[i-1]='\0';                                                  //remove the last dot

  return name;
}
 

/* the dns servers are there in /etc/resolv.conf file */
void get_dns_servers()
{
  FILE *fp;
  char line[200] , *p;/*
  if((fp = fopen("/etc/resolv.conf" , "r")) == NULL)
  {
    printf("Failed opening /etc/resolv.conf file \n");
  }
   
  while(fgets(line , 200 , fp))
  {
    if(line[0] == '#')
    {
        continue;
    }
    if(strncmp(line , "nameserver" , 10) == 0)
    {
        p = strtok(line , " ");
        p = strtok(NULL , " ");
    }
  }*/
   
  //strcpy(dns_servers[0] , "208.67.222.222");
  strcpy(dns_servers[0] , "8.8.8.8");
  strcpy(dns_servers[1] , "8.8.4.4");
  //strcpy(dns_servers[1] , "208.67.220.220");
}
 

/* dns compression scheme - converts www.redhat.com to 3www6redhat3com */
void changetoDnsFormat(unsigned char* dns,unsigned char* host) 
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


/* converts the ip-address to dns format for reverse lookup */
void changeIPtoDnsFormat(unsigned char* dns,unsigned char* hostip)
{
  int i, iplen, j, prevDot, counter;

  unsigned char revip[100];

  iplen = strlen(hostip);

  prevDot = iplen;
  counter =0;

  for(i=iplen-1; i>=0; --i)
  {
    if(i==0)
    {
      for( j = i; j<prevDot; ++j)
      {
        revip[counter++] = hostip[j]; 
      } 
    }
    else if(hostip[i]=='.')
    {
      for( j = i+1; j<prevDot; ++j)
      {
        revip[counter++] = hostip[j]; 
      }
      revip[counter++]='.';
      prevDot = i;
    }
  }

  revip[i] = '\0';

  strcat(revip, ".in-addr.arpa.");

  changetoDnsFormat(dns, revip);
}









