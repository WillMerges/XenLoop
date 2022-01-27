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



#ifndef _XENFIFO_H_
#define _XENFIFO_H_

#include <xen/xenbus.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>

#include <xen/hypercall.h>
#include <xen/driver_util.h>
#include <xen/gnttab.h>
#include <xen/evtchn.h>

#include "debug.h"

#define MAX_FIFO_PAGES 64
#define MAX_FIFO_PAGE_ORDER 6  

/* 
 * Shared FIFO descriptor page 
 * 	sizeof(xf_descriptor_t) should be no bigger than PAGE_SIZE
 */
struct xf_descriptor {
	u8 suspended_flag;
	unsigned int num_pages; 
	int grefs[MAX_FIFO_PAGES]; /* grant references to FIFO pages -- Not too many 
				      pages expected right now */
	int dgref; 
	uint16_t max_data_entries; /* Max 64K. Should be power of 2. */ 
	uint32_t front, back; /* Range of these indices must be power of 2 
				 and larger than max_data_entries.*/ 
	uint32_t index_mask; 
};
typedef struct xf_descriptor xf_descriptor_t;

struct xf_handle {

	domid_t remote_id; 
	xf_descriptor_t *descriptor;
	void *fifo; 
	int listen_flag; 

	
	struct vm_struct *descriptor_vmarea;
	grant_handle_t dhandle; 
	struct vm_struct *fifo_vmarea;
	grant_handle_t fhandles[MAX_FIFO_PAGES]; 

};
typedef struct xf_handle xf_handle_t;

/******************* Listener functions *********************************/
extern xf_handle_t *xf_create(domid_t remote_domid, unsigned int entry_size, unsigned int entry_order);
extern int xf_destroy(xf_handle_t *xfl);
/******************* Connector functions *********************************/
extern xf_handle_t *xf_connect(domid_t remote_domid, int remote_gref);
extern int xf_disconnect(xf_handle_t *xfc);

/************** FUNCTIONS FOR BOTH LISTENER AND CONNECTOR ******************
 * Although it may be best if one side sticks to push/back and other to pop/front 
 ****************************************************************************/

static inline uint32_t xf_size(xf_handle_t *h)
{
	return h->descriptor->back - h->descriptor->front;
}


static inline uint32_t xf_free(xf_handle_t *h)
{
	return  h->descriptor->max_data_entries - xf_size(h);
}

static inline int xf_full(xf_handle_t *h)
{
	return ( xf_size(h) == h->descriptor->max_data_entries );
}

static inline int xf_empty(xf_handle_t *h)
{
	return ( xf_size(h) == 0 );
}

/*
 * Push a data value onto the back of the FIFO. 
 * Returns 0 on success, -1 on failure
 */
static inline uint32_t xf_push(xf_handle_t *handle) 
{
	xf_descriptor_t *des = handle->descriptor;

	if( xf_full(handle) ) {
		return -1;
	}

	des->back++; 

	return 0;
}

/*
 * Push n data values onto the back of the FIFO. 
 * Returns 0 on success, -1 on failure
 */
static inline uint32_t xf_pushn(xf_handle_t *handle, uint32_t n) 
{
	xf_descriptor_t *des = handle->descriptor;

	if( xf_free(handle) < n ) {
		return -1;
	}

	des->back += n;

	return 0;
}

/*
 * Remove a data value from the front of the FIFO. 
 * Returns value is 0 on success, -1 on failure
 */
static inline uint32_t xf_pop(xf_handle_t *handle) 
{ 
	xf_descriptor_t *des = handle->descriptor;

	if( xf_empty(handle) ) {
		return -1;
	}

	des->front++; 

	return 0;
}

/*
 * Remove n data values from the front of the FIFO. 
 * Returns value is 0 on success, -1 on failure
 */
static inline uint32_t xf_popn(xf_handle_t *handle, uint32_t n) 
{ 
	xf_descriptor_t *des = handle->descriptor;

	if( xf_size(handle) < n ) {
		return -1;
	}

	des->front += n; 

	return 0;
}

/*
 * Return a reference to a free data value at the back of the FIFO. 
 * xf_back does not remove the data from the FIFO. Call xf_push to do so.
 * Returns  NULL if FIFO is FULL
 */
#define xf_back(handle, type) (  					\
{ 									\
type * _xf_ret;								\
do									\
{									\
	xf_descriptor_t *_xf_des = handle->descriptor;			\
	type *_xf_fifo = (type *)handle->fifo;				\
									\
	if( xf_full(handle) ) {						\
		_xf_ret = NULL;						\
		break;							\
	}								\
									\
	_xf_ret = &_xf_fifo[_xf_des->back & _xf_des->index_mask];	\
 									\
} while (0);								\
_xf_ret;								\
}									\
)

/*
 * Return a reference to the data value at the front of the FIFO. 
 * xf_front does not remove the data from the FIFO. Call xf_pop to do so.
 * Returns  NULL if FIFO is empty
 */
#define xf_front(handle, type) (  				\
{ 									\
type * _xf_ret;								\
do									\
{									\
	xf_descriptor_t *_xf_des = handle->descriptor;			\
	type *_xf_fifo = (type *)handle->fifo;				\
									\
	if( xf_empty(handle) ) {					\
		_xf_ret = NULL;						\
		break;							\
	}								\
									\
	_xf_ret = &_xf_fifo[_xf_des->front & _xf_des->index_mask];	\
 									\
} while (0);								\
_xf_ret;								\
}									\
)

/*
 * Return pointer to entry at position index in FIFO
 * Doesn't check if index is within front and back
 */
#define xf_entry(handle, type, index) (					\
{ 									\
type * _xf_ret;								\
do									\
{									\
	xf_descriptor_t *_xf_des = handle->descriptor;			\
	type *_xf_fifo = (type *)handle->fifo;				\
									\
	_xf_ret = &_xf_fifo[ (_xf_des->front + index) & _xf_des->index_mask]; \
 									\
} while (0);								\
_xf_ret;								\
}									\
)

#endif // _XENFIFO_H_
