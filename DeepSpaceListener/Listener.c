#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h>
typedef unsigned char byte;

typedef struct IPs{
   byte first;
   byte second;
   byte third;
   byte fourth;
   unsigned int ip;
}IP;

// Returns a short integer from raw data that is captured from the network.
short ShortUnmarshal(byte** buffer){
   short salida;
   byte* pSalida = (byte*) &salida;
   
   // Since we need the bytes to be on a different endian we just swap the bytes
   // using memory manipulation.
   pSalida[1] = **buffer;
   pSalida[0] = *(*buffer+1);

   *buffer += sizeof(short);
   return salida;
}


// Reads four bytes from |buffer| and reconstructs the IP address on |out|.
void IPUnmarshal(byte** buffer, IP* out){

    // Get the bytes of the IP address out of the buffer.
   out->first = **buffer;
   out->second = *(*buffer+1);
   out->third = *(*buffer+2);
   out->fourth = *(*buffer+3);

   // Advance the input pointer the size of an IP address (size of an 4 byte
   // integer)
   *buffer += sizeof(int);
   
   // Reconstruct the integer that represents the IP address using memory
   // manipulation;
   byte* pointer = (byte*) &out->ip;

   pointer[0] = out->fourth;
   pointer[1] = out->third;
   pointer[2] = out->second;
   pointer[3] = out->first;
}

// Shows the hex dump of memory on screen.
void printbuffer(byte* buffer, int size){
   for(int i=0; i<size; i++)
       printf("%02x ", buffer[i]);
   printf("\n");
}

// Prints |ip| on screen using dotted notation.
void printIPDotted(IP ip){
   printf("%d.%d.%d.%d\n", ip.first, ip.second, ip.third, ip.fourth);
}

// Analizes a packet of size |size| from the buffer |buffer|. This function 
// discards any packet that is not a TCP syn packet.
void AnalyzePacket(byte *buffer, int size){
    const int mac_size = 6;

    // First we skip the ethernet data, the 2 mac addresses.
    //
    // In order to manipulate the packet we will use a temporary buffer.
   byte* temp = buffer + 2*mac_size;

   // Unmarshal the type of packet if it is not an IP packet (0x0800) discard
   // it.
   short sType = ShortUnmarshal(&temp);
   if (sType != 0x0800)
       return;

   // Get the header length that is stored on on the first byte of the ip 
   // packet.
   //
   // The first half of the first byte is the ip version, the second half is the
   // header length, we are interested on getting the second half.
   int header_length = *temp & 0x0F;

   // Since the header_length field stores the number of 4-byte words in the
   // header. Multiply it by 4 to get the total header length;
   header_length *= 4;

   // Get the total length, this is the bytes 3 and 4 of the packet.
   // 
   //
   // First skip the first short integer and then unmarshal the total length.
   temp += sizeof(short);
   short total_length = ShortUnmarshal(&temp);

   // Now check that the protocol of the packet is either udp or tcp.
   //
   // Advance 4 bytes for Identification, flags and fragment offset and
   // one byte for time to live.
   temp += sizeof(int) + sizeof(byte);
   byte protocol = *temp;
   temp += sizeof(byte);

   // If the protocol is not TCP or UDP drop this packet.
   const short UDP = 0x11;
   const short TCP = 0x06;
   if (protocol != 0x06) return;

   // Skip the header checksum and unmarshal the source and destination
   // IP Addresses.
   temp += sizeof(short);

   // Unmarshal and reconstruct the source and destination IP address.
   IP source, destination;
   IPUnmarshal(&temp, &source);
   IPUnmarshal(&temp, &destination);

   // Since there could be options, skip the rest of the IP header using
   // the header length. We are expecting that the normal Header (without 
   // options) is 20 bytes long.
   const int normal_IP_length = 20;
   temp += normal_IP_length-20;

   // Now analyze the TCP or UDP part of the buffer.
   //
   // If the protocol is UDP only get the source and destination port;
   unsigned short source_port, destination_port;
   source_port = ShortUnmarshal(&temp);
   destination_port = ShortUnmarshal(&temp);

   if (protocol == TCP){
      // In case that the port is tcp, check that this packet is a SYN
      // packet, this may change in the future, for now only analyze SYN 
      // packtes.
      
      // Advance the pointer two 4 byte integers and one byte in order to skip
      // sequence number, ack number, offset and reserved. 
      temp += 2*sizeof(int) + sizeof(byte);

      // Now check if the packet is a syn, in any other case drop the packet.
      byte flags = *temp;
      if(flags != 0x02) return;
   }
/*
   // Since the packet was not dropped, print all the information.
   printf("Header Length: %d\n", header_length);
   printf("Total Length: %d\n", total_length);

   // Print the IP Addresses
   printf("Source IP: \n");
   printIPDotted(source);
   printf("Destination IP: \n");
   printIPDotted(destination);

   // Print the transport data.
   printf("Transport protocol: ");
   if (protocol == TCP)
       printf("TCP\n");
   else
       printf("UDP\n");
   printf("Source port: %d\n", source_port);
   printf("Destination port: %d\n", destination_port);
   // Print the hexdump of the buffer.
   printbuffer(buffer, size);
   printf("\n\n");
*/
   time_t now = time(NULL);
   FILE* out_file = fopen("log.txt", "a+");
   fprintf(out_file, "%d %d %d.%d.%d.%d %d:%d:%d\n", source_port, destination_port,
           source.first, source.second, source.third, source.fourth, 
           localtime(&now)->tm_hour, localtime(&now)->tm_min,
           localtime(&now)->tm_sec);
   fclose(out_file);
}

int main(){

    // Variables used to control the socket
   int saddr_size, data_size;
   struct sockaddr saddr;
   struct in_addr in;

   // Declare a raw socket that captures all the packets from the kernel. 
   // (some sort of a TCP_Dump).
   int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   if(sockfd < 0){
      printf("Socket Error!\n");
      return -1;
   }

   // Allocate a buffer with enough size.
   byte *buffer = (byte *) malloc(65536);

   // Start capturing packets
   while(1){
      saddr_size = sizeof(saddr);
      memset(buffer, 0, 65536);
      data_size = recvfrom(sockfd, buffer, 65536, 0, &saddr, &saddr_size);

      // If data_size is less than 0 that means we got an error.
      if(data_size < 0){
         printf("Error in socket\n");
         return -1;
      }

      // Print the hex dump and analyze the packet
      AnalyzePacket(buffer, data_size);
   }

}
