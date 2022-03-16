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

#include <asm/xen/hypercall.h>
//#include <asm/xen/driver_util.h>
//#include <xen/gnttab.h>
#include <xen/grant_table.h>
//#include <xen/evtchn.h>
#include <xen/events.h>
#include <xen/xenbus.h>

#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#include "discovery.h"
#include "debug.h"


static u8 guest_macs[MAX_MAC_NUM][ETH_ALEN];
static int num_of_macs = 0;
//static char *nic = "eth0\0  ";
struct net_device *NIC = NULL;
static domid_t guest_domids[MAX_MAC_NUM];

static struct task_struct *discover_thread;

static char* nic = NULL;
module_param(nic,charp,0660);

int store_domid_mac(char* domid, char* mac)
{
	char *pEnd = mac;
	int i;

	for (i=0; i < (ETH_ALEN-1); i++) {
		guest_macs[num_of_macs][i] = simple_strtol(pEnd, &pEnd, 16);
		pEnd++;
	}

	guest_macs[num_of_macs][ETH_ALEN-1] = simple_strtol(pEnd, NULL, 16);

	guest_domids[num_of_macs] = (domid_t)simple_strtoul(domid, NULL, 10);
	num_of_macs++;

	return 0;
}



static int probe_vifs(char *guest)
{
        int err = 0;
        char **dir;
	char *path=NULL, *guest_vif, *macstr, *domid;
        unsigned int i, dir_n;

	TRACE_ENTRY;

	domid = xenbus_read(XBT_NIL, guest, "domid", NULL);
	if ( IS_ERR(domid) ) {
		EPRINTK("xenbus_read domid error path=%s \n", guest);
		err = PTR_ERR(domid);
		return err;
	}

	guest_vif = kasprintf(GFP_KERNEL, "%s/device/vif", guest);
	if (!guest_vif) {
		EPRINTK("guest_vif kasprintf failed\n");
		err = -ENOMEM;
		goto out;
	}

        dir = xenbus_directory(XBT_NIL, guest_vif, "", &dir_n);
        if (IS_ERR(dir)) {
		DB("xenbus_directory guest_vif %s failed\n", guest_vif);
		kfree(guest_vif);
                err =  PTR_ERR(dir);
		goto out;
	}

        for (i = 0; i < dir_n; i++) {
		path = kasprintf(GFP_KERNEL, "%s/%s",guest_vif, dir[i]);
		if (!path) {
			EPRINTK("kasprintf failed dir[%d]=%s \n", i, dir[i]);
			err = -ENOMEM;
			goto out1;
		}

		macstr = xenbus_read(XBT_NIL, path, "mac", NULL);
		if ( IS_ERR(macstr) ) {
			EPRINTK("xenbus_read error path=%s \n", path);
			err = PTR_ERR(macstr);
			goto out2;
		}

		store_domid_mac(domid, macstr);

		kfree(macstr);
        }
out2:
	kfree(path);
out1:
        kfree(dir);
	kfree(guest_vif);
out:
	kfree(domid);

	TRACE_EXIT;
        return err;
}




static int probe_domains(void)
{
        int ret,err = 0,status;
        char **dir;
	char * path=NULL,* xenloop=NULL;
        unsigned int i, dir_n;

	TRACE_ENTRY;
        dir = xenbus_directory(XBT_NIL, "/local/domain", "", &dir_n);
        if (IS_ERR(dir))
                return PTR_ERR(dir);

        for (i = 1; i < dir_n; i++) {

		path = kasprintf(GFP_KERNEL, "/local/domain/%s", dir[i]);
		if (!path) {
			EPRINTK("kasprintf failed dir[%d]=%s \n", i, dir[i]);
			err = -ENOMEM;
			goto out;
		}

		xenloop = kasprintf(GFP_KERNEL, "%s/xenloop", path);
		if (!xenloop) {
			EPRINTK("kasprintf for xenloop failed.\n");
			err = -ENOMEM;
			kfree(path);
			goto out;
		}

		ret = xenbus_scanf(XBT_NIL, xenloop, "xenloop","%d", &status);
		if (ret != 1) {
			DB( "reading xenstore xenloop status failed, err = %d domainid = %s\n",ret, dir[i]);
			err = 1;

			kfree(xenloop);
			kfree(path);
			continue;
		}

		if (status)
			probe_vifs(path);

		kfree(xenloop);
		kfree(path);
	}
	TRACE_EXIT;


out:
	kfree(dir);
	return err;
}





inline void net_send(struct sk_buff * skb, u8 * dest)
{
	ethhdr * eth;
	int ret;

	TRACE_ENTRY;

	skb->network_header = 0;

	skb->len = headers;
	skb->data_len = 0;
	skb_shinfo(skb)->nr_frags 	= 0;
	skb_shinfo(skb)->frag_list 	= NULL;
	skb->tail = headers; // TODO check if this is an offset or not

	skb->dev 	= NIC;
	skb->protocol 	= htons(ETH_P_TIDC);
	eth 		= (ethhdr *) skb->data;
	eth->h_proto 	= htons(ETH_P_TIDC);
	memcpy(eth->h_dest, dest, ETH_ALEN);

	memcpy(eth->h_source, NIC->dev_addr, ETH_ALEN);

	if((skb_shinfo(skb) == NULL)) {
		WARN_ON(1);
		TRACE_ERROR;
	}

	SKB_LINEAR_ASSERT(skb);


	if((ret = dev_queue_xmit(skb))) {
		DB("Non-zero return code: %d %s", ret,
		   skb_shinfo(skb) ? "good" : "bad");

		TRACE_ERROR;
	}

}


static void send_mac(u8* dest)
{
	message_t *m;
	struct sk_buff *skb;

	TRACE_ENTRY;
	BUG_ON(!(skb = alloc_skb(headers, GFP_ATOMIC)));

	m = (message_t *) (skb->data + LINK_HDR);

	memset(m, 0, MSGSIZE);
	m->type = XENLOOP_MSG_TYPE_SESSION_DISCOVER;
	m->domid= 0;
	m->mac_count = num_of_macs;
	memcpy(m->mac, guest_macs, num_of_macs*ETH_ALEN);
 	memcpy(m->guest_domids, guest_domids, num_of_macs*sizeof(domid_t));

	net_send(skb, dest);

	TRACE_EXIT;
}

static int update_guests(void *useless)
{
	int i,ret;

	TRACE_ENTRY;

        while(!kthread_should_stop()) {
		num_of_macs = 0;
		ret = probe_domains();
		if (ret)  {
			DB("Failed probe_domains, module not installed\n");
		}

		if (num_of_macs > 1) {
			for (i=0; i < num_of_macs; i++)
				send_mac(guest_macs[i]);
		}

		msleep_interruptible(DISCOVER_TIMEOUT*HZ);
	}

	TRACE_EXIT;
	return 0;
}



static int __init discover_init(void)
{
	int ret = 0;
    struct net_device* dev;

	if(nic == NULL) {
		EPRINTK("no NIC device name passed in as module parameter, exiting\n");
		rc = -EBADPARAM;
		goto out;
	}

	TRACE_ENTRY;

	//NIC = dev_get_by_name(&init_net, nic);

	/*
    // TODO this is a spin lock, an rcu lock may be faster
    // this function is only called once however, so it's probably fine
    read_lock(&dev_base_lock);

    dev = first_net_device(&init_net);
    while(dev) {
        // if an interface satisfies all of this, it's probably an active Ethernet NIC
        if(dev->addr_len == ETH_ALEN &&
           dev->flags & IFF_UP &&
           dev->flags & IFF_RUNNING &&
           !(dev->flags & IFF_LOOPBACK) &&
           !(dev->flags & IFF_NOARP)) {

            printk(KERN_INFO "found device [%s]\n", dev->name);

            dev_hold(dev); // needs to be freed by dev_put in exit function
            NIC = dev;
            break;
        }

        dev = next_net_device(dev);
    }

    read_unlock(&dev_base_lock);
	*/

	NIC = dev_get_by_name(&init_net, nic);

    if(!NIC) {
		DB("discovery_init(): Could not find network card %s\n", nic);
		ret = -ENODEV;
		goto out;
	}

	DPRINTK("Discovery module initialized. Using dom0 source MAC addr = " MAC_FMT " .\n", MAC_NTOA(NIC->dev_addr));

    discover_thread = kthread_run(update_guests, NULL, "discover");

out:
	TRACE_EXIT;
	return ret;
}


static void __exit discover_exit(void)
{
	TRACE_ENTRY;

	kthread_stop(discover_thread);

	if(NIC) dev_put(NIC);

	DPRINTK("Discovery module terminated\n");

	TRACE_EXIT;
}

module_init(discover_init);
module_exit(discover_exit);

MODULE_LICENSE("GPL");
