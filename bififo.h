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


#ifndef BIFIFO_H
#define BIFIFO_H

#include "xenfifo.h"

#define BF_PACKET 0
#define BF_RESPONSE 1

#define BF_WAITING 0
#define BF_PROCESSING 1
#define BF_FREE 2

/*
 * No pointers please since the data is copied into FIFO for the other domain to pick up.
 * Try to keep the sizeof(bf_data_t) a power of 2 since it has to fit within 2^page_order
 */
struct bf_data {
	uint8_t type;
	uint16_t status;
	uint32_t pkt_info;
};
typedef struct bf_data bf_data_t;

struct bf_handle {
	domid_t remote_domid;
	xf_handle_t *out;
	xf_handle_t *in;
	int port;
	int irq;
};
typedef struct bf_handle bf_handle_t;

#define BF_GREF_IN(handle) (handle->in->descriptor->dgref)
#define BF_GREF_OUT(handle) (handle->out->descriptor->dgref)
#define BF_SUSPEND_IN(handle) (handle->in->descriptor->suspended_flag)
#define BF_SUSPEND_OUT(handle) (handle->out->descriptor->suspended_flag)
#define BF_EVT_PORT(handle) (handle->port)
#define BF_EVT_IRQ(handle) (handle->irq)

extern bf_handle_t *bf_create(domid_t, int);
extern bf_handle_t *bf_connect(domid_t, int, int, int);
extern void bf_destroy(bf_handle_t *);
extern void bf_disconnect(bf_handle_t *);
extern void bf_notify(int port);
extern irqreturn_t bf_callback(int rq, void *dev_id);
extern void migrate_save(void *);
extern void migrate_send(void);

#define XENLOOP_STATUS_INIT 	1
#define XENLOOP_STATUS_LISTEN 	2
#define XENLOOP_STATUS_CONNECTED 4
#define XENLOOP_STATUS_SUSPEND   8

typedef struct Entry {
	struct list_head mapping;
	struct list_head ip_mapping;
	u8		mac[ETH_ALEN];
	u32		ip;
	u8		status;
	u8		listen_flag;
	u8		retry_count;
	domid_t		domid;
	ulong		timestamp;
	u8 del_timer;
	struct timer_list ack_timer;
	bf_handle_t 	*bfh;
} Entry;


#endif // BIFIFO_H
