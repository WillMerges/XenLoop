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


#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/genhd.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>

#include <asm/xen/hypercall.h>
//#include <xen/driver_util.h>
#include <xen/grant_table.h>
#include <xen/events.h>

#include "debug.h"
#include "xenfifo.h"
#include "bififo.h"
#include "maptable.h"

extern HashTable mac_domid_map;
extern wait_queue_head_t swq;
extern struct net_device *NIC;
extern Entry*	lookup_bfh(HashTable *, void *);

void bf_notify(int port)
{
	struct evtchn_send op;
	int ret;

	TRACE_ENTRY;

	memset(&op, 0, sizeof(op));
	op.port = port;

	ret = HYPERVISOR_event_channel_op(EVTCHNOP_send, &op);
	if ( ret != 0 ) {
		EPRINTK("Unable to signal on event channel\n");
		goto out;
	}

	TRACE_EXIT;
	return;

out:
	TRACE_ERROR;

}

static inline void copy_large_pkt(bf_data_t * mdata, struct sk_buff *skb, xf_handle_t *xfh)
{
	char *pback, *pfront, *pfifo;
	int num_entries, len, len1, len2, pkt_len;

	TRACE_ENTRY;

        skb_reserve(skb, 2 + ETH_HLEN);
        skb_put(skb, mdata->pkt_info);

	pkt_len = mdata->pkt_info;
	num_entries = pkt_len/sizeof(bf_data_t);
	if (pkt_len % sizeof(bf_data_t))
		num_entries++;


	pfifo = (char *)xfh->fifo;
	pfront = (char *)xf_entry(xfh, bf_data_t, 1);
	pback = (char *)xf_entry(xfh, bf_data_t, num_entries);

	BUG_ON(!pfifo);
	BUG_ON(!pfront);
	BUG_ON(!pback);

	if( pback >= pfront ) {
		memcpy(skb->data, pfront, pkt_len);
	} else {

		len1 = (pfifo + xfh->descriptor->max_data_entries*sizeof(bf_data_t)) - pfront;
		len = (len1 >= pkt_len) ? pkt_len : len1;
		memcpy(skb->data,  pfront, len);

		len2 = pkt_len - len;
		if (len2 > 0) {
			memcpy(skb->data + len, pfifo, len2);
		}
	}

        //skb->mac.raw = skb->data - ETH_HLEN;
        skb->mac_header = (__u16)(skb->data - skb->head) + ETH_HLEN;
        skb->ip_summed = CHECKSUM_UNNECESSARY;
        skb->pkt_type = PACKET_HOST;
        skb->protocol = htons(ETH_P_IP);
        skb->dev = NIC;
        skb_shinfo(skb)->nr_frags = 0;
        skb_shinfo(skb)->frag_list = NULL;
        skb_shinfo(skb)->frags[0].bv_page = NULL;

	TRACE_EXIT;
}

static inline struct sk_buff * copy_packet(xf_handle_t * xfh)
{
	struct sk_buff *skb = NULL;
	bf_data_t * data;
	int n, ret;

	TRACE_ENTRY;

	data = xf_front(xfh, bf_data_t);
	BUG_ON(!data);

        skb = alloc_skb(data->pkt_info + 2 + ETH_HLEN, GFP_ATOMIC);
        if (!skb) {
		DB("Cannot allocate skb for size %d\n", data->pkt_info + 2 + ETH_HLEN);
                goto out;
	}

	copy_large_pkt(data, skb, xfh);

	n = data->pkt_info/sizeof(bf_data_t) + 1;
	if (data->pkt_info % sizeof(bf_data_t))
		n++;

	ret = xf_popn(xfh, n);
	BUG_ON( ret < 0 );

out:
	TRACE_EXIT;
	return skb;
}

void recv_packets(bf_handle_t *bfh)
{
	static DEFINE_SPINLOCK(recv_lock);
	struct sk_buff *skb;
	unsigned long flags;

	TRACE_ENTRY;

	spin_lock_irqsave(&recv_lock, flags);

	while( !xf_empty(bfh->in) ) {

		skb = copy_packet(bfh->in);
		if (!skb)
			break;

		spin_unlock_irqrestore(&recv_lock, flags);

		// DPRINTK("packet received through xenloop\n");
		netif_rx(skb);

		// this isn't needed anymore, i think
		// NIC->last_rx = jiffies;

		spin_lock_irqsave(&recv_lock, flags);
	}

	spin_unlock_irqrestore(&recv_lock, flags);

	TRACE_EXIT;
}



irqreturn_t bf_callback(int rq, void *dev_id)
{
	bf_handle_t *bfh = (bf_handle_t *)dev_id;

	TRACE_ENTRY;

	BUG_ON(!check_descriptor(bfh));

	if (BF_SUSPEND_IN(bfh) || BF_SUSPEND_OUT(bfh)) {
		Entry *e = lookup_bfh(&mac_domid_map, bfh);
		BUG_ON(!e);

		e->status = XENLOOP_STATUS_SUSPEND;

		wake_up_interruptible(&swq);
		TRACE_EXIT;
		return IRQ_HANDLED;
	}

	recv_packets(bfh);

	TRACE_EXIT;
	return IRQ_HANDLED;
}

void free_evtch(int port, int irq, void *dev_id)
{
	struct evtchn_close op;
	int ret;

	TRACE_ENTRY;

	if(irq)
		unbind_from_irqhandler(irq, dev_id);

	if(port) {
		memset(&op, 0, sizeof(op));
		op.port = port;
		ret = HYPERVISOR_event_channel_op(EVTCHNOP_close, &op);
		if ( ret != 0 )
			EPRINTK("Unable to cleanly close event channel\n");
	}

	TRACE_EXIT;
}




int create_evtch(domid_t rdomid, int *port, int *irq, void *arg)
{
	struct evtchn_alloc_unbound op;
	int ret;

	TRACE_ENTRY;

	if(!irq || !port )
		BUG();

	memset(&op, 0, sizeof(op));
	op.dom = DOMID_SELF;
	op.remote_dom = rdomid;

	ret = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &op);
	if ( ret != 0 ) {
		EPRINTK("Unable to allocate event channel\n");
		goto out;
	}
	*port = op.port;

	ret = bind_evtchn_to_irqhandler(op.port, bf_callback, SA_RESTART, "bf_listener", arg);
	if ( ret  <= 0 ) {
		EPRINTK("Unable to bind event channel to callback\n");
		goto out1;
	}

	*irq = ret;
	DB("unbound port = %d irq = %d\n", *port, *irq);

	TRACE_EXIT;
	return 0;

out1:
	free_evtch(*port, *irq, arg);
out:
	TRACE_ERROR;
	return -1;
}

void bf_destroy(bf_handle_t *bfl)
{
	TRACE_ENTRY;

	if(!bfl) {
		EPRINTK("bfl = NULL\n");
		goto err;
	}

	if(bfl->in)
		xf_destroy(bfl->in);

	if(bfl->out)
		xf_destroy(bfl->out);

	free_evtch(bfl->port, bfl->irq, (void *)bfl);

	kfree(bfl);

	TRACE_EXIT;
	return;
err:
	TRACE_ERROR;
}


bf_handle_t *bf_create(domid_t rdomid, int entry_order)
{
	bf_handle_t *bfl = NULL;
	int ret;
	TRACE_ENTRY;

	bfl = (bf_handle_t *) kmalloc(sizeof(bf_handle_t), GFP_KERNEL);
	if(!bfl) {
		EPRINTK("Can't allocate bfl\n");
		goto err;
	}

	memset(bfl, 0, sizeof(bf_handle_t));
	bfl->remote_domid = rdomid;
	bfl->out = xf_create(rdomid, sizeof(bf_data_t), entry_order);
	bfl->in = xf_create(rdomid, sizeof(bf_data_t), entry_order);
	if(!bfl->out || !bfl->in) {
		EPRINTK("Can't allocate bfl->in %p or bfl->out %p\n", bfl->in, bfl->out);
		goto err;
	}

	ret = create_evtch(rdomid, &bfl->port, &bfl->irq, (void *)bfl);
	if(ret < 0) {
		EPRINTK("Can't allocate event channel\n");
		goto err;
	}

	TRACE_EXIT;
	return bfl;

err:
	bf_destroy(bfl);
	TRACE_ERROR;
	return NULL;
}

int bind_evtch(domid_t rdomid, int rport, int *local_port, int *local_irq, void *arg)
{

	struct evtchn_bind_interdomain op;
	int ret;
	TRACE_ENTRY;

	if(!local_irq || !local_port )
		BUG();

	memset(&op, 0, sizeof(op));
	op.remote_dom = rdomid;
	op.remote_port = rport;

	ret = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain, &op);
	if ( ret != 0 ) {
		EPRINTK("Unable to bind event channel\n");
		goto out;
	}
	*local_port = op.local_port;

	ret = bind_evtchn_to_irqhandler(op.local_port, bf_callback, SA_RESTART, "bf_connector", arg);
	if ( ret  <= 0 ) {
		EPRINTK("Unable to bind event channel to callback\n");
		goto out1;
	}
	*local_irq = ret;

	DB("bound port = %d irq = %d\n", *local_port, *local_irq);

	TRACE_EXIT;
	return 0;

out1:
	free_evtch(*local_port, *local_irq, arg);
out:
	TRACE_ERROR;
	return -1;
}

void bf_disconnect(bf_handle_t *bfc)
{
	TRACE_ENTRY;

	if(!bfc) {
		EPRINTK("bfc = NULL\n");
		goto err;
	}

	if(bfc->in)
		xf_disconnect(bfc->in);

	if(bfc->out)
		xf_disconnect(bfc->out);

	free_evtch(bfc->port, bfc->irq, (void *)bfc);

	kfree(bfc);

	TRACE_EXIT;
	return;
err:
	TRACE_ERROR;

}

bf_handle_t *bf_connect(domid_t rdomid, int rgref_in, int rgref_out, int rport)
{
	bf_handle_t *bfc = NULL;
	int ret;
	TRACE_ENTRY;

	bfc = (bf_handle_t *) kmalloc(sizeof(bf_handle_t), GFP_KERNEL);
	if(!bfc) {
		EPRINTK("Can't allocate bfc\n");
		goto err;
	}

	memset(bfc, 0, sizeof(bf_handle_t));
	bfc->remote_domid = rdomid;
	bfc->out = xf_connect(rdomid, rgref_out);
	bfc->in = xf_connect(rdomid, rgref_in);
	if(!bfc->out || !bfc->in) {
		EPRINTK("Can't allocate bfc->in %p or bfc->out %p\n", bfc->in, bfc->out);
		goto err;
	}

	EPRINTK("made it passed xf_connect\n");

	ret = bind_evtch(rdomid, rport, &bfc->port, &bfc->irq, (void *)bfc);
	if(ret < 0) {
		EPRINTK("Can't bind to event channel\n");
		goto err;
	}

	TRACE_EXIT;
	return bfc;
err:
	bf_disconnect(bfc);
	TRACE_ERROR;
	return NULL;
}
