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


#include "debug.h"
#include "xenfifo.h"
#include <linux/vmalloc.h>

/*
 * Create a listener-end of FIFO to which a remote domain can connect
 *	Called by the listener end of FIFO
 *
 * @remote_domid - remote domain  allowed to connect
 * @entry_size - size of each entry in FIFO
 * @entry_order - maximum size of FIFO as a  power of 2. Current max 256. Max maxsize = 2^16.
 *
 * Returns: pointer to the shared FIFO struct
 */
xf_handle_t *xf_create(domid_t remote_domid, unsigned int entry_size, unsigned int entry_order)
{
	unsigned long page_order = get_order(entry_size*(1<<entry_order));
	xf_handle_t * xfl = NULL;
	int i;

	TRACE_ENTRY;

	if (entry_order > 16) {
		EPRINTK("More than 64K entries requested\n");
		goto err;
	}

	if( sizeof(xf_descriptor_t) > PAGE_SIZE)
		BUG();


	if( page_order > MAX_FIFO_PAGE_ORDER) {
		EPRINTK("%d > 2^MAX_PAGE_ORDER pages requested for FIFO\n", 1<<page_order);
		goto err;
	}

	xfl = kmalloc(sizeof(xf_handle_t), GFP_ATOMIC);
	if(!xfl) {
		EPRINTK("Out of memory\n");
		goto err;
	}
	memset(xfl, 0, sizeof(xf_handle_t));


	xfl->descriptor = (xf_descriptor_t *) __get_free_page(GFP_ATOMIC);
	if(!xfl->descriptor) {
		EPRINTK("Cannot allocate descriptor memory page for FIFO\n");
		goto err;
	}

	xfl->fifo = (void *) __get_free_pages(GFP_ATOMIC, page_order);
	if(!xfl->fifo) {
		EPRINTK("Cannot allocate buffer memory pages for FIFO\n");
		goto err;
	}


	xfl->listen_flag = 1;
	xfl->remote_id = remote_domid;
	xfl->descriptor->suspended_flag = 0;
	xfl->descriptor->num_pages = (1<<page_order);
	xfl->descriptor->max_data_entries = (1<<entry_order);
	xfl->descriptor->index_mask = ~(0xffffffff<<entry_order);
	xfl->descriptor->front = xfl->descriptor->back = 0;

	xfl->descriptor->dgref = gnttab_grant_foreign_access(remote_domid, virt_to_mfn(xfl->descriptor), 0);
	if ( xfl->descriptor->dgref < 0) {
		EPRINTK("Cannot share descriptor gref page %p\n", xfl->descriptor);
		goto err;
	}

	for( i=0; i < xfl->descriptor->num_pages; i++) {

		xfl->descriptor->grefs[i] =
				gnttab_grant_foreign_access(remote_domid,
						virt_to_mfn(((uint8_t *)xfl->fifo) + i*PAGE_SIZE), 0);

		if ( xfl->descriptor->grefs[i] < 0) {
			EPRINTK("Cannot share FIFO %p page %d\n", xfl->fifo, i);
			while(--i) gnttab_end_foreign_access_ref(xfl->descriptor->grefs[i], 0);
			gnttab_end_foreign_access_ref(xfl->descriptor->dgref, 0);
			goto err;
		}
	}

	TRACE_EXIT;
	return xfl;

err:
	if( xfl) {
		if( xfl->descriptor) free_page((unsigned long)xfl->descriptor);
		if( xfl->fifo ) free_pages((unsigned long)xfl->fifo, page_order);
		kfree(xfl);
	}

	TRACE_ERROR;
	return NULL;
}

/*
 * Destroy the FIFO
 * 	Can only be called by the creator (listener)
 *
 * Returns: 0 on success, -1 on failure
 */
int xf_destroy(xf_handle_t *xfl)
{
	int i;
	TRACE_ENTRY;

	if(!xfl || !xfl->descriptor || !xfl->fifo) {
		EPRINTK("xfl OR descriptor OR fifo is NULL\n");
		goto err;
	}

	for(i=0; i < xfl->descriptor->num_pages; i++)
		gnttab_end_foreign_access_ref(xfl->descriptor->grefs[i], 0);
	gnttab_end_foreign_access_ref(xfl->descriptor->dgref, 0);

	DPRINTK("free_pages / kfree in xf_destroy\n");

	free_pages((unsigned long)xfl->fifo, get_order(xfl->descriptor->num_pages*PAGE_SIZE));
	free_page((unsigned long)xfl->descriptor);

	kfree(xfl);

	TRACE_EXIT;
	return 0;

err:
	TRACE_ERROR;
	return -1;
}


/*
 * Connect to a FIFO listener on another domain
 */

xf_handle_t *xf_connect(domid_t remote_domid, int remote_gref)
{
	xf_handle_t *xfc = NULL;
	struct gnttab_map_grant_ref map_op;
	int ret;
	int i;
	TRACE_ENTRY;

	xfc = kmalloc(sizeof(xf_handle_t), GFP_ATOMIC);
	if(!xfc) {
		EPRINTK("Out of memory\n");
		goto err;
	}
	memset(xfc, 0, sizeof(xf_handle_t));

	// allocate a page of our own for the descriptor
	// xfc->descriptor = (xf_descriptor_t*) kmalloc(PAGE_SIZE, GFP_ATOMIC);
	xfc->descriptor = (xf_descriptor_t*) __get_free_page(GFP_ATOMIC);

	if(!xfc->descriptor) {
		EPRINTK("Cannot allocate memory page for descriptor\n");
		goto err;
	}

	// map our descriptor page to the other guest VMs descriptor page they shared with us
	gnttab_set_map_op(&map_op, (unsigned long)xfc->descriptor,
				GNTMAP_host_map, remote_gref, remote_domid);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &map_op, 1);
	if( ret || (map_op.status != GNTST_okay) ) {
		EPRINTK("HYPERVISOR_grant_table_op failed ret = %d status = %d\n", ret, map_op.status);
		goto err;
	}

	xfc->listen_flag = 0;
	xfc->remote_id = remote_domid;
	xfc->dhandle = map_op.handle;

	// allocate our own pages for the FIFO based on the number of pages listed in the descriptor
	xfc->fifo = (void*) kmalloc(xfc->descriptor->num_pages * PAGE_SIZE, GFP_ATOMIC);

	if(!xfc->fifo) {
		EPRINTK("Cannot allocate %u memory pages for FIFO\n", xfc->descriptor->num_pages);
		goto err;
	}

	// map the guest VMs FIFO pages to our own pages
	for(i=0; i < xfc->descriptor->num_pages; i++) {
		gnttab_set_map_op(&map_op,
				(unsigned long)(xfc->fifo + i*PAGE_SIZE),
				GNTMAP_host_map, xfc->descriptor->grefs[i], remote_domid);

		ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &map_op, 1);

		if( ret || (map_op.status != GNTST_okay) ) {
			struct gnttab_unmap_grant_ref unmap_op;

			EPRINTK("HYPERVISOR_grant_table_op failed ret = %d status = %d\n", ret, map_op.status);
			while(--i >= 0) {
				gnttab_set_unmap_op(&unmap_op,
					(unsigned long)xfc->fifo + i*PAGE_SIZE,
					GNTMAP_host_map, xfc->fhandles[i]);
				ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmap_op, 1);
				if( ret )
					EPRINTK("HYPERVISOR_grant_table_op unmap failed ret = %d \n", ret);
			}

			gnttab_set_unmap_op(&unmap_op,
				(unsigned long)xfc->descriptor,
				GNTMAP_host_map, xfc->dhandle);
			ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmap_op, 1);
			if( ret )
				EPRINTK("HYPERVISOR_grant_table_op unmap failed ret = %d \n", ret);

			goto err;
		}

		xfc->fhandles[i] = map_op.handle;
	}

	TRACE_EXIT;
	return xfc;

err:
	if(xfc) {
		if(xfc->fifo) {
			// free_pages((unsigned long)xfc->fifo, xfc->descriptor->num_pages);
			kfree(xfc->fifo);
		}

		if(xfc->descriptor) {
			free_page((unsigned long)xfc->descriptor);
			// kfree(xfc->descriptor);
		}

		kfree(xfc);
	}
	TRACE_ERROR;
	return NULL;
}

int xf_disconnect(xf_handle_t *xfc)
{
	struct gnttab_unmap_grant_ref unmap_op;
	int i, num_pages, ret;
	TRACE_ENTRY;

	if(!xfc || !xfc->descriptor || !xfc->fifo) {
		EPRINTK("Something is NULL\n");
		goto err;
	}

	num_pages = xfc->descriptor->num_pages;
	for(i=0; i < num_pages; i++) {
		gnttab_set_unmap_op(&unmap_op, (unsigned long)(xfc->fifo + i*PAGE_SIZE),
			GNTMAP_host_map, xfc->fhandles[i]);
		ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmap_op, 1);
		if( ret )
			EPRINTK("HYPERVISOR_grant_table_op unmap failed ret = %d \n", ret);
	}

	gnttab_set_unmap_op(&unmap_op, (unsigned long)xfc->descriptor,
			GNTMAP_host_map, xfc->dhandle);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmap_op, 1);
	if( ret )
		EPRINTK("HYPERVISOR_grant_table_op unmap failed ret = %d \n", ret);

	// free_pages((unsigned long)xfc->fifo, num_pages);
	// free_page((unsigned long)xfc->descriptor);
	DPRINTK("kfree in xf_disconnect\n");

	kfree(xfc->fifo);
	// BUG here
	// kernel panic when xfc->descriptor is freed
	// kfree(xfc->descriptor);
	free_page((unsigned long)xfc->descriptor);
	//
	// kfree(xfc);

	DPRINTK("memory freed!\n");

	TRACE_EXIT;
	return 0;

err:
	TRACE_ERROR;
	return -1;
}
