/*
 *  XenLoop -- A High Performance Inter-VM Network Loopback
 *
 *  Installation and Usage instructions
 *
 *  Authors:
 *  	Jian Wang - Binghamton University (jianwang@cs.binghamton.edu)
 *  	Kartik Gopalan - Binghamton University (kartik@cs.binghamton.edu)
 *
 *  Copyright (C) 2007-2009 Kartik Gopalan, Jian Wang
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */



#ifndef _MAIN_H_
#define _MAIN_H_

#define	MAX_MAC_NUM	10
#define MAX_RETRY_COUNT 5

#define ETH_P_TIDC			0x8888
typedef struct timeval      timeval;
typedef struct list_head    list_head;
typedef struct page         page;
typedef struct ethhdr 		ethhdr;
typedef struct net_device 	net_device;
typedef struct packet_type 	packet_type;

#define XENLOOP_MSG_TYPE_SESSION_DISCOVER 	77
#define XENLOOP_MSG_TYPE_SESSION_DISCOVER_ACK 	78
#define XENLOOP_MSG_TYPE_CREATE_CHN		2
#define XENLOOP_MSG_TYPE_CREATE_ACK 		4
#define XENLOOP_MSG_TYPE_DESTROY_CHN 		8

#define XENLOOP_ENTRY_ORDER 15


typedef struct message {
	u8		type;
	u8		mac_count;
	u8		mac[MAX_MAC_NUM][ETH_ALEN];
	domid_t domid;
	domid_t	guest_domids[MAX_MAC_NUM];

	int		gref_in;
	int		gref_out;
	int		remote_port;
} message_t;

typedef struct skb_queue{
        struct sk_buff *head;
        struct sk_buff *tail;
        int count;
} skb_queue_t;


#define LINK_HDR 			sizeof(struct ethhdr)
#define MSGSIZE				sizeof(message_t)
const int 		headers = LINK_HDR + MSGSIZE;

#endif /* _MAIN_H_ */
