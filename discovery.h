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



#ifndef _DISCOVERY_H_
#define _DISCOVERY_H_

#define DISCOVER_TIMEOUT 1

typedef struct ethhdr 		ethhdr;
#define XENLOOP_MSG_TYPE_SESSION_DISCOVER 	77



#define ETH_P_TIDC			0x8888

#define	MAX_MAC_NUM	 10

typedef struct message {
	u8		type;

	u8		mac_count;
	u8		mac[MAX_MAC_NUM][ETH_ALEN];
	domid_t 	domid;
	domid_t	        guest_domids[MAX_MAC_NUM];

	int		gref_in;
	int		gref_out;
	uint32_t		remote_port;

} message_t;

#define LINK_HDR 			sizeof(struct ethhdr)
#define MSGSIZE				sizeof(message_t)
const int 		headers = LINK_HDR + MSGSIZE;


#endif /* _DISCOVERY_H_ */
