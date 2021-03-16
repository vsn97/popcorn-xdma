/******************************************************************
 *msg_xdma.c
 * Messaging transport layer over FPGA interconnect fabric (XDMA + 25G Ethernet Subsystem)
 * Authors: Naarayanan <naarayananrao@vt.edu>
 ******************************************************************/
#define _GNU_SOURCE

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <asm/pci.h>
#include <linux/spinlock.h>
#include <asm/msr.h>
#include <linux/kthread.h>
#include <asm/io.h>
#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <rdma/rdma_cm.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include <popcorn/stat.h>
#include <popcorn/pcn_kmsg.h>
#include <linux/delay.h>
#include "common.h"
#include "ring_buffer.h"

/* Xilinx Vendor ID and Device ID programmed by Vivado Design Suite
   Can be changed according to the device specifications */

#define VEND_ID 0x10EE
#define DEV_ID 0x903F

// Region of interest for this application.
//If PCIe to AXI Lite Master Interface is enabled then this region/BAR would change to 2.

#define XDMA_MSB_MASK 0xFFFFFFFF00000000LL
#define XDMA_LSB_MASK 0xFFFFFFFFLL

#define XDMA_SIZE 0x10000
#define BYPASS_SIZE 0x1000

#define MAX_RECV_DEPTH	((PAGE_SIZE << (MAX_ORDER - 1)) / PCN_KMSG_MAX_SIZE)
#define MAX_SEND_DEPTH	(MAX_RECV_DEPTH)
#define XDMA_SLOT_SIZE PAGE_SIZE * 2
#define XDMA_SLOTS 256

static unsigned int use_rb_thr = PAGE_SIZE / 2;


/* BAR Addresses of the FPGA PCIe */

static unsigned long ctl_address;
static unsigned long bypass_address;

/* XDMA Register Offsets */

#define h2c_ctl 0x04
#define c2h_ctl 0x1004
#define h2c_stat 0x44
#define c2h_stat 0x1044

#define h2c1_ctl 0x104
#define c2h1_ctl 0x1104
#define h2c1_stat 0x144
#define c2h1_stat 0x1144

#define ch_irq 0x2044
#define irq_mask 0x2018
#define irq_enable 0x2014

//#define ch1_off 0x100

//static DEFINE_SPINLOCK(__xdma_slots_lock)

static struct pci_dev *pci_dev;
static void __iomem *xdma_bypass;
static void __iomem *xdma_ctl;
static char *__xdma_sink_address;
static dma_addr_t __xdma_sink_dma_address;
static struct workqueue_struct *wq;
static struct task_struct *tsk;

/* Index of Receive Queue */

static int page_ix = 0;
static int nid;

static int KV[XDMA_SLOTS];

/*
   static struct device dma_dev = {
   .init_name = "dma_dev",
   .coherent_dma_mask =
   }
   */

struct work_hdr {
	enum {
		WORK_TYPE_RECV,
		WORK_TYPE_XDMA,
		WORK_TYPE_SEND,
	} type;
};

enum {
	SW_FLAG_MAPPED = 0,
	SW_FLAG_FROM_BUFFER = 1,
};
enum {
	KMSG = 0,
	PAGE = 1,
};

enum {

	CTL = 0,
	BYPASS = 1,
};
enum {
	c2h = 0,
	h2c = 1,
};

enum {
	TO_DEVICE = 0,
	FROM_DEVICE = 1,
};

/* Send Buffer for pcn_kmsg*/

struct send_work {
	struct work_hdr header;
	void *addr;
	u64 dma_addr;
	u32 length;
	struct send_work *next;
	struct completion *done;
	unsigned long flags;
};

static struct send_work *curr_sw;

/* Receive Buffer for pcn_kmsg */

struct recv_work {
	struct work_struct work_q;
	struct work_hdr header;
	void *addr;
	u64 dma_addr;
	u32 length;
};

/* XDMA Work Buffer */

struct xdma_work {

	int nid;
	struct work_hdr header;
	struct xdma_work *next;
	u32 length;
	void *addr;
	dma_addr_t dma_addr;
	u64 remote_addr;
	unsigned long flags;
	struct completion *done;

};

static struct xdma_work *curr_xw ;

struct queue {
	unsigned int tail;
	unsigned int head;
	unsigned int size;
	unsigned int nr_entries;
	struct send_work **work_list;
};

typedef struct queue queue_t;

struct queue_r {
	unsigned int tail;
	unsigned int head;
	unsigned int size;
	unsigned int nr_entries;
	struct recv_work **work_list;
};

typedef struct queue_r queue_tr;


struct rb_alloc_header {
	struct send_work *work;
	unsigned int flags;
	unsigned int magic;

};

const unsigned int rb_alloc_header_magic = 0xbad7face;

static DEFINE_SPINLOCK(send_work_pool_lock);
static struct ring_buffer xdma_send_buff = {};
static struct send_work *send_work_pool = NULL;

static queue_t *send_queue;
static queue_tr *recv_queue;

static DEFINE_SPINLOCK(xdma_work_pool_lock);
static struct xdma_work *xdma_work_pool = NULL;


static void write_register(u32 value, void *iomem)
{
	iowrite32(0x00, iomem);
	iowrite32(value,iomem);
}

static inline u32 read_register(void *iomem)
{
	return ioread32(iomem);
}

/* Converting the kernel virtual address to a dma capable physical address - Replacing ib_dma_map_single()-rdma.c function */

static u64 __dma_map(void *addr, size_t size, int x)
{
	if(!x) {
		return dma_map_single(&pci_dev->dev, addr, size, DMA_TO_DEVICE);
	} else {
		return dma_map_single(&pci_dev->dev, addr, size, DMA_FROM_DEVICE);
	}
}

/* DMA Mapping Error verification */

static int __verify_dma_mapping(u64 dma_addr)
{
	return dma_mapping_error(&pci_dev->dev, dma_addr);
}

/* DMA Unmapping */

static void dma_unmap(u64 dma_addr, size_t size, int y)
{
	if(!y) {
		dma_unmap_single(&pci_dev->dev, dma_addr, size, DMA_TO_DEVICE);
	} else {
		dma_unmap_single(&pci_dev->dev, dma_addr, size, DMA_FROM_DEVICE);
	}
}

/* Remapping the kernel physical regions to a kernel virtual address to perform R/W operations */

static void __iomem *__remap_regions(unsigned long address, size_t size)
{
	return ioremap(address, size);
}

static void __update_recv_index(queue_tr *q, int i)
{
	u32 addr_msb, addr_lsb;
	dma_addr_t dma_addr;
	void *addr;
	if(i == q->nr_entries)	{
		i = 0;
		q->tail = -1;
		q->size = 0;
	}

	dma_addr = q->work_list[i]->dma_addr;
	addr = q->work_list[i]->addr;

	addr_msb = (u32)((dma_addr & XDMA_MSB_MASK) >> 32);
	addr_lsb = (u32)(dma_addr & XDMA_LSB_MASK);

	write_register(addr_msb, (u32 *)xdma_bypass + 10);
	write_register(addr_lsb, (u32 *)xdma_bypass + 11);
	write_register(PCN_KMSG_MAX_SIZE, (u32 *)xdma_bypass + 12);
	//PCNPRINTK("Updated Recv Index: %llx\n", read_register((u32 *)xdma_bypass + 11));
}

int queue_empty(queue_t* q){
	if (q == NULL){
		return -1;
	}else if(q->size == 0) {
		return 1;
	}else {
		return 0;
	}
}

int queue_full(queue_t* q){
	if (q == NULL){
		return -1;
	}else if(q->size == q->nr_entries){
		return 1;
	}else{
		return 0;
	}
}

int queue_emptyr(queue_tr* q){
	if (q == NULL){
		return -1;
	}else if(q->size == 0) {
		return 1;
	}else {
		return 0;
	}
}

int queue_full_r(queue_tr* q){
	if (q == NULL) {
		return -1;
	} else if(q->size == q->nr_entries) {
		return 1;
	} else {
		return 0;
	}
}


static int __enq_send(struct send_work *work)
{
	while(queue_full(send_queue));
	send_queue->tail = (send_queue->tail + 1) % send_queue->nr_entries;
	send_queue->work_list[send_queue->tail] = work;
	send_queue->size++;
	return 0;
}

static int __get_recv_index(queue_tr *q)
{
	q->tail = (q->tail + 1) % q->nr_entries;
	q->size++;
	//PCNPRINTK("Recv Index: %d\n", q->tail);
	return q->tail;
}

static int __xdma_transfer(dma_addr_t dmaAddr, size_t size, int x)
{

	u32 addr_lsb, addr_msb;

	//Mapping the physical address to virtual addresses to perform R/W operations with size

	if(!xdma_bypass) {
		goto remap;
	}

	addr_msb = (u32)((dmaAddr & XDMA_MSB_MASK) >> 32);
	addr_lsb = (u32)(dmaAddr & XDMA_LSB_MASK);

	//PCNPRINTK("MSB and LSB : %lx and %lx\n", addr_msb, addr_lsb);

	/* KMSGs are sent through Channel 0 and Page data through Channel 1 of XDMA */

	if(!x) {
		write_register(addr_msb, (u32 *)xdma_bypass + 1);
		write_register(addr_lsb, (u32 *)xdma_bypass + 2);
		write_register(size, (u32 *)xdma_bypass + 3);
	} else {
		write_register(addr_msb, (u32 *)xdma_bypass + 30);
		write_register(addr_lsb, (u32 *)xdma_bypass + 31);
		write_register(size, (u32 *)xdma_bypass + 32);
	}

	//PCNPRINTK("\n Initiating Transfer .... \n");

	return 0;

remap:
	PCNPRINTK("Mapping Failed!..");
	return 1;

}

static struct send_work *__get_xdma_send_work_map(struct pcn_kmsg_message *msg, size_t size)
{
	unsigned long flags;
	struct send_work *work;
	void *map_start = NULL;

	spin_lock_irqsave(&send_work_pool_lock, flags);
	work = send_work_pool;
	send_work_pool = work->next;
	spin_unlock_irqrestore(&send_work_pool_lock, flags);

	work->done = NULL;
	work->flags = 0;

	if(!msg) {
		struct rb_alloc_header *rbah;
		work->addr = ring_buffer_get_mapped(&xdma_send_buff, 
			sizeof(struct rb_alloc_header) + size, &work->dma_addr);

		//PCNPRINTK("No msg in the xdma_send_work_map function: %lx\n", size);

		if(likely(work->addr)) {
			//PCNPRINTK("Inside the Likely function\n");
			work->dma_addr += sizeof(struct rb_alloc_header);
		} else {
			/* Kmalloc when the ring buffer is full */
			if(WARN_ON_ONCE("ring buffer is full"))
			{
				//PCNPRINTK("Ring Buffer Utilization: %lu\n", ring_buffer_usage(&xdma_send_buff));
			}

			work->addr = kmalloc(sizeof(struct rb_alloc_header) + size, GFP_ATOMIC);

			map_start = work->addr + sizeof(struct rb_alloc_header);

			set_bit(SW_FLAG_FROM_BUFFER, &work->flags);
		}

		rbah = work->addr;
		rbah->work = work;
	} else {
		//PCNPRINTK("Message exists inside the xdma send work map function:%d and %lx\n",
				   //msg->header.type, msg->header.size);
		work->addr = msg;
		map_start = work->addr;
	}

	if(map_start) {
		int ret;
		work->dma_addr = __dma_map(map_start, size, TO_DEVICE);
		ret = __verify_dma_mapping(work->dma_addr);
		BUG_ON(ret);
		set_bit(SW_FLAG_MAPPED, &work->flags);

	}

	work->length = size;
	return work;
}

static struct send_work *__get_xdma_send_work(size_t size)
{
	return __get_xdma_send_work_map(NULL, size);
}

/*Global XDMA work pool */

static int __refill_xdma_work(int xdma_slot)
{
	int i;
	int nr_refilled = 0;

	struct xdma_work *work_list = NULL;
	struct xdma_work *last_work = NULL;
	//PCNPRINTK("inside refill xdma work done\n");
	for (i = 0; i < xdma_slot; i++) {
		struct xdma_work *xw;

		xw = kzalloc(sizeof(*xw), GFP_KERNEL);
		if (!xw) goto out;

		xw->header.type = WORK_TYPE_XDMA;

		xw->remote_addr = 0;
		xw->dma_addr = 0;
		xw->length = 0;

		if (!last_work) last_work = xw;
		xw->next = work_list;
		work_list = xw;
		nr_refilled++;
	}

out:
	spin_lock(&xdma_work_pool_lock);

	if (work_list) {
		last_work->next = xdma_work_pool;
		xdma_work_pool = work_list;
	}

	spin_unlock(&xdma_work_pool_lock);
	BUG_ON(nr_refilled == 0);
	return nr_refilled;

}

static struct xdma_work *__get_xdma_work(dma_addr_t dma_addr, void *addr, size_t size, dma_addr_t raddr)
{
	struct xdma_work *xw;
	//PCNPRINTK("Inside xdma_get_work function: %llx and %llx and %llx and %lx\n", (unsigned long)addr, dma_addr, raddr, size);
	spin_lock(&xdma_work_pool_lock);
	xw = xdma_work_pool;
	xdma_work_pool = xdma_work_pool->next;
	spin_unlock(&xdma_work_pool_lock);
	//PCNPRINTK("Work Pool done\n");
	if (!xdma_work_pool) {

		__refill_xdma_work(XDMA_SLOTS);
	}

	xw->dma_addr = dma_addr;
	xw->addr = addr;
	xw->length = size;
	xw->remote_addr = raddr;

	return xw;
}

static void __put_xdma_work(struct xdma_work *xw)
{
	spin_lock(&xdma_work_pool_lock);
	xw->next = xdma_work_pool;
	xdma_work_pool = xw;
	spin_unlock(&xdma_work_pool_lock);
}

/* Function to enqueue the send work to the send queue */

static int __send_sw(struct send_work *work)
{
	int ret, i;
	struct pcn_kmsg_message *msg = work->addr;
	dma_addr_t dma_addr = work->dma_addr;
	size_t size = work->length;
	//PCNPRINTK("Inside the __send_sw function: %lx and %llx\n", work->length, work->dma_addr);
	//PCNPRINTK("___ SW FRAME ___");
	//for(i = 0; i< 65; i++) {
	//	printk("%lx\n", read_register((u32 *)msg + i));
	//}
	//PCNPRINTK("___ SW FRAME END___");
	/* To check if the XDMA engine is free */

	while((read_register((u32*)xdma_bypass+0x02)));
	ret = __xdma_transfer(dma_addr, size, KMSG);
	curr_sw = work;

	if(ret) return ret;

	return 0;
}

static int __send_xdma_work(struct xdma_work *xw, size_t size)
{
	int ret, i;
	void *addr;
	//PCNPRINTK("Inside the xdma work send function\n");
	dma_addr_t dmaAddr;
	dmaAddr = xw->dma_addr;
	addr = bus_to_virt(dmaAddr);

	while(read_register((u32 *)xdma_bypass + 31));
	curr_xw = xw;
	ret = __xdma_transfer(dmaAddr, size, PAGE);
	if(ret) return ret;

	return 0;
}

static void __put_xdma_send_work(struct send_work *work)
{
	unsigned long flags;
	//PCNPRINTK("Put xdma send work\n");

	if(test_bit(SW_FLAG_MAPPED, &work->flags)) {
		dma_unmap(work->dma_addr, work->length, TO_DEVICE);
	}

	if(test_bit(SW_FLAG_FROM_BUFFER, &work->flags))
	{
		if(unlikely(test_bit(SW_FLAG_MAPPED, &work->flags))) {
			kfree(work->addr);
		} else {
			ring_buffer_put(&xdma_send_buff, work->addr);
		}
	}

	spin_lock_irqsave(&send_work_pool_lock, flags);
	work->next = send_work_pool;
	send_work_pool = work;
	spin_unlock_irqrestore(&send_work_pool_lock, flags);
	//PCNPRINTK("Exiting the put xdma send work");
}


static int deq_send(queue_t *q)
{
	struct send_work *work;
	int ret;
	if (!q){
		return -1;

	} else if (queue_empty(q) == 1){
		return 1;
	} else {

		work = q->work_list[q->head];
		q->head = (q->head + 1) % q->nr_entries;
		q->size--;
		ret = __send_sw(work);
		if(ret) goto out;

		return 0;
	}

out:
	PCNPRINTK("Sending KMSG Failed!\n");
	return 1;
}

/* To send kernel messages to the other node */

int xdma_kmsg_send(int nid, struct pcn_kmsg_message *msg, size_t size)
{
	struct send_work *work;
	int ret;
	int i;
	DECLARE_COMPLETION_ONSTACK(done);

	//PCNPRINTK("Inside xdma send function and size: %d and %d and %lx and %lx\n", msg->header.type, msg->header.from_nid, size, msg->header.size);

	if(size <= use_rb_thr) {
		work = __get_xdma_send_work(size);
		memcpy(work->addr + sizeof(struct rb_alloc_header), msg, size);
	} else {
		work = __get_xdma_send_work_map(msg, size);
	}


	work->done = &done;


	ret = __enq_send(work);

	if(ret) goto out;

	if(!try_wait_for_completion(&done)){
		ret = wait_for_completion_io_timeout(&done, 60 *HZ);
		if(!ret) {
			PCNPRINTK("MEssage waiting failed\n");
			ret = -ETIME;
			goto out;
		}
	}
	//PCNPRINTK("Message Send Done\n");
	return 0;

out:
	__put_xdma_send_work(work);
	return ret;
}

/* To perform of DMA of pages requested by the remote node */

int xdma_kmsg_write(int to_nid, dma_addr_t raddr, void *addr, size_t size)
{

	DECLARE_COMPLETION_ONSTACK(done);
	struct xdma_work *xw;
	dma_addr_t dma_addr;
	int ret;

	//PCNPRINTK("Inside xdma write function\n");

	dma_addr = __dma_map(addr, size, TO_DEVICE);
	ret = __verify_dma_mapping(dma_addr);

	//PCNPRINTK("Done mapping Page: %llx\n", dma_addr);

	BUG_ON(ret);

	xw = __get_xdma_work(dma_addr, addr, size, raddr);
	BUG_ON(!xw);
	//PCNPRINTK("Got the xdma work\n");
	xw->done = &done;

	ret = __send_xdma_work(xw, size);
	if(ret) {
		PCNPRINTK("Cannot do XDMA KMSG write\n");
		goto out;
	}

	if(!try_wait_for_completion(&done)) {
		wait_for_completion(&done);
	}
	//PCNPRINTK("Page Write done\n");

out:
	dma_unmap(dma_addr, size, TO_DEVICE);
	__put_xdma_work(xw);
	return ret;
}

int xdma_kmsg_post(int nid, struct pcn_kmsg_message *msg, size_t size)
{
	struct rb_alloc_header *rbah = (struct rb_alloc_header *)msg - 1;
	struct send_work *work = rbah->work;
	int ret, i;

	//PCNPRINTK("Inside xdma POST function\n");
	//PCNPRINTK("Contents inside the POST function: %d and %d and %lx\n", msg->header.type, msg->header.from_nid, msg->header.size);

	ret = __enq_send(work);
	if(ret) {
		__put_xdma_send_work(work);
		return ret;
	}

	return 0;
}

void xdma_kmsg_put(struct pcn_kmsg_message *msg)
{
	struct rb_alloc_header *rbah = (struct rb_alloc_header *)msg - 1;
	struct send_work *work = rbah->work;
	//PCNPRINTK("Inside xdma put function\n");
	//PCNPRINTK("Contents inside the PUT function: %d and %d and %lx\n", msg->header.type, msg->header.from_nid, msg->header.size);
	__put_xdma_send_work(work);
}

static int __config_pcie(struct pci_dev *dev)
{
	int ret;
	pci_dev_put(pci_dev);

	ret = pci_enable_device(pci_dev);
	if(ret) return ret;

	return 0;
}

static unsigned long __pci_map(struct pci_dev *dev, int BAR)
{
	unsigned long addr = pci_resource_start(pci_dev, BAR);
	if(!addr) {
		return 0;
	}

	return addr;
}

void xdma_kmsg_done(struct pcn_kmsg_message *msg)
{
	//PCNPRINTK("xdma kmsg done\n");
	//kfree(msg);
}

struct pcn_kmsg_message *xdma_kmsg_get(size_t size)
{
	struct send_work *work = __get_xdma_send_work(size);
	struct rb_alloc_header *rbah = work->addr;

	//PCNPRINTK("Inside xdma kmsg get function\n");

	return (struct pcn_kmsg_message *)(rbah + 1);
}

int xdma_kmsg_read(int from_nid, void *addr, dma_addr_t raddr, size_t size)
{
	return -EPERM;
}

void xdma_kmsg_stat(struct seq_file *seq, void *v)
{
	if (seq) {
		seq_printf(seq, POPCORN_STAT_FMT,
			   (unsigned long long)ring_buffer_usage(&xdma_send_buff),
#ifdef CONFIG_POPCORN_STAT
			   (unsigned long long)xdma_send_buff.peak_usage,
#else
			   0ULL,
#endif
			   "Send buffer usage");
	}
}

static int send_handler(void* arg0)
{
	bool was_frozen;
	int i;
	//PCNPRINTK("Send Handler is ready\n");

	while (!kthread_should_stop())
	{
		//printk("Waiting for Send Queue\n");
		if(queue_empty(send_queue))	{
			//printk("Queue empty");
			msleep(100);
		} else {
			i = deq_send(send_queue);
			if(i) {
				printk("Error sending message\n");
			}
		}
	}

	return 0;
}


unsigned int queue_size(queue_t* q){
	if (q == NULL){
		return - 1;
	} else {
		return q->size;
	}
}

void free_queue(queue_t* q){
	int i;
	for(i = 0; i<q->size; i++) {
		kfree(q->work_list[i]);
	}

	kfree(q->work_list);
	kfree(q);
}

void free_queue_r(queue_tr* q){
	int i;
	for(i = 0; i<q->size; i++) {
		kfree(q->work_list[i]);
	}

	kfree(q->work_list);
	kfree(q);
}


static queue_t* __setup_send_queue(int entries)
{
	queue_t* send_q = (queue_t*)kmalloc(sizeof(queue_t), GFP_KERNEL);
	int i;
	if(!send_q) {
		goto out;
	}
	//PCNPRINTK("Send QUEUE Created: %d\n\r",entries);

	send_q->tail = -1;
	send_q->head = 0;
	send_q->size = 0;
	send_q->nr_entries = entries;
	send_q->work_list = kmalloc(entries * sizeof(struct send_work *), GFP_KERNEL);

	for(i = 0; i<entries; i++) {
		send_q->work_list[i] = kmalloc(sizeof(struct send_work), GFP_KERNEL);
	}

	return send_q;

out:
	PCNPRINTK("Send Queue Failed\n");
	return NULL;
}

static int __update_xdma_index(dma_addr_t dma_addr, size_t size)
{
	u32 addr_msb, addr_lsb;
	//PCNPRINTK("Inside the xdma_index function: %llx\n", dma_addr);
	addr_msb = (u32)((dma_addr & XDMA_MSB_MASK) >> 32);
	addr_lsb = (u32)(dma_addr & XDMA_LSB_MASK);

	write_register(addr_msb, (u32 *)xdma_bypass + 20);
	write_register(addr_lsb, (u32 *)xdma_bypass + 21);
	write_register(size, (u32 *)xdma_bypass + 22);
	++page_ix;
	return 0;
}

static int __check_page_index(int i)
{
	if(i == XDMA_SLOTS)
	{
		if(KV[0] == 0) {
			//PCNPRINTK("Page index updated\n");
			page_ix = 0;
			return 0;
		} else {
			PCNPRINTK("Receive Buffer Full\n\r");
			while(KV[0] != 0);
			page_ix = 0;
			return 0;
		}
	} else if(KV[i]) {
		PCNPRINTK("Buffer not unpinned\n\r");
		return -1;
	} else {
		return i;
	}

	return 0;
}

struct pcn_kmsg_xdma_handle *xdma_kmsg_pin_buffer(void *msg, size_t size)
{
	int ret;
	struct pcn_kmsg_xdma_handle *xh = kmalloc(sizeof(*xh), GFP_KERNEL);
	//PCNPRINTK("Inside the Pin Buffer function\n");
	if(size > XDMA_SLOT_SIZE) {
		PCNPRINTK("Buffer too large to pin");
		return ERR_PTR(-EINVAL);
	}

	ret = __check_page_index(page_ix);
	if(ret < 0) {
		PCNPRINTK("Error in the KV\n");
		return NULL;
	}

	xh->addr = __xdma_sink_address + XDMA_SLOT_SIZE * page_ix;
	xh->dma_addr =	__xdma_sink_dma_address + XDMA_SLOT_SIZE * page_ix;
	xh->flags = page_ix;
	KV[page_ix] = 1;

	//PCNPRINTK("Pin Index: %d and %llx\n", ret, xh->dma_addr);

	__update_xdma_index(xh->dma_addr, PAGE_SIZE);
	return xh;
}

void xdma_kmsg_unpin_buffer(struct pcn_kmsg_xdma_handle *handle)
{
	//PCNPRINTK("Inside the unpin buffer\n");
	KV[handle->flags] = 0;
	kfree(handle);
}


struct pcn_kmsg_transport transport_xdma = {
	.name = "xdma",
	.features = PCN_KMSG_FEATURE_XDMA,

	.get = xdma_kmsg_get,
	.put = xdma_kmsg_put,
	.stat = xdma_kmsg_stat,

	.post = xdma_kmsg_post,
	.send = xdma_kmsg_send,
	.done = xdma_kmsg_done,

	.pin_xdma_buffer = xdma_kmsg_pin_buffer,
	.unpin_xdma_buffer = xdma_kmsg_unpin_buffer,
	.xdma_write = xdma_kmsg_write,
	.xdma_read = xdma_kmsg_read,

};

static u32 __get_node_info(void)
{
	u32 ret;

	ret = ioread32((u32 *)xdma_bypass);
	return ret;
}

static void __channel_interrupts_disable(int z, int x)
{
	int i;
	//PCNPRINTK("Inside channel interrupts disable\n");
	if(z) {
		if(!x) {
			//write_register(0x00,  (u32 *)(xdma_ctl + h2c_ctl));
			write_register(0x01, (u32 *)(xdma_ctl + irq_mask));
			read_register((u32 *)(xdma_ctl + h2c_stat));
			i = read_register((u32 *)(xdma_ctl + irq_enable));
			write_register(i | 0x01, (u32 *)(xdma_ctl + irq_enable));
			while(read_register(xdma_ctl + ch_irq));
			//PCNPRINTK("Status of IRQ: %lx\n", read_register(xdma_ctl + ch_irq));
		} else {
			//write_register(0x00, (u32 *)(xdma_ctl + ch1_off + h2c_ctl));
			write_register(0x02, (u32 *)(xdma_ctl + irq_mask));
			read_register((u32 *)(xdma_ctl + h2c1_stat));
			i = read_register((u32 *)(xdma_ctl + irq_enable));
			write_register(i | 0x02, (u32 *)(xdma_ctl + irq_enable));
			while(read_register(xdma_ctl + ch_irq));
			//PCNPRINTK("Status of IRQ: %lx\n", read_register(xdma_ctl + ch_irq));
		}
	} else {
		if(!x) {
		   //write_register(0x00, (u32 *)(xdma_ctl + c2h_ctl));
		    write_register(0x04, (u32 *)(xdma_ctl + irq_mask));
			read_register((u32 *)(xdma_ctl + c2h_stat));
			i = read_register((u32 *)(xdma_ctl + irq_enable));
			write_register(i | 0x04, (u32 *)(xdma_ctl + irq_enable));
			while(read_register(xdma_ctl + ch_irq));
			//PCNPRINTK("Status of IRQ: %lx\n", read_register(xdma_ctl + ch_irq));
		} else {
			//write_register(0x00, (u32 *)(xdma_ctl + ch1_off + c2h_ctl));
			write_register(0x08, (u32 *)(xdma_ctl + irq_mask));
			read_register((u32 *)(xdma_ctl + c2h1_stat));
			i = read_register((u32 *)(xdma_ctl + irq_enable));
			write_register(i | 0x08, (u32 *)(xdma_ctl + irq_enable));
			while(read_register(xdma_ctl + ch_irq));
			//PCNPRINTK("Status of IRQ: %lx\n", read_register(xdma_ctl + ch_irq));
		}
	}

	//PCNPRINTK("Exiting channel interrupts disable\n");
}

static void process_msg(struct work_struct *work)
{
	struct recv_work *rw;
	struct pcn_kmsg_message *msg;
	int i;
	rw = container_of(work, struct recv_work, work_q);
	if(!rw)	{
		printk("No RW Created\n");
	}

	//PCNPRINTK("Inside the process_msg function: %llx\n",(unsigned long)rw->addr);
	msg = rw->addr;
	//PCNPRINTK("Sending message to process: %d and %d and %lx\n", msg->header.from_nid, msg->header.type, msg->header.size);
	pcn_kmsg_process(msg);

}

static void __process_sent(struct send_work *work)
{
	if(work->done) {
		complete(work->done);
	}
	__put_xdma_send_work(work);
}

static void __page_sent(struct xdma_work *xw)
{
	if(xw->done){
		complete(xw->done);
	}
}

static int __process_received(struct recv_work *rws)
{
	static struct recv_work rw;
	struct pcn_kmsg_message *msg;
	void *addr;
	bool ret;
	int i;
	//PCNPRINTK("Address and DMA of the receiver: %lx and %llx\n", (unsigned long)rws->addr, rws->dma_addr);
	//addr = bus_to_virt(rws->dma_addr);
	//PCNPRINTK("Virtual Address of the DMA Receiver: %lx\n", (unsigned long)addr);

	msg = rws->addr;
	//PCNPRINTK("__MSG FRAME __\n");
	//for(i = 0; i< 60; i++) {
		//printk("%lx\n", read_register((u32 *)msg + i));
	//}

	//PCNPRINTK("___ MSG FRAME END\n");

	if(msg->header.type < 0 || msg->header.type >= PCN_KMSG_TYPE_MAX || 
	 msg->header.size < 0 || msg->header.size > PCN_KMSG_MAX_SIZE){
		printk(KERN_ERR "------- Faulty Work Rejected -----------!!\n");
		return 0;
	}

	INIT_WORK(&rw.work_q, process_msg);
	rw.addr = rws->addr;
	ret = queue_work(wq, &rw.work_q);

	if(ret == false) {
		PCNPRINTK("Work already exists\n");
		return 1;
	}

	return 0;
}

static __init queue_tr* __setup_recv_buffer(int entries)
{
	queue_tr* recv_q = (queue_tr*)kmalloc(sizeof(queue_tr), GFP_KERNEL);
	int i, index;
	if(!recv_q) {
		goto out;
	}
	//PCNPRINTK("Max recv Depth: %d\n\r", entries);
	recv_q->tail = -1;
	recv_q->head = 0;
	recv_q->size = 0;
	recv_q->nr_entries = entries;
	recv_q->work_list = kmalloc(entries * sizeof(struct recv_work *), GFP_KERNEL);

	for(i = 0; i < entries; i++) {
		recv_q->work_list[i] = kmalloc(sizeof(struct recv_work), GFP_KERNEL);
		recv_q->work_list[i]->header.type = WORK_TYPE_RECV;
		recv_q->work_list[i]->addr = kmalloc(PCN_KMSG_MAX_SIZE, GFP_KERNEL);
		recv_q->work_list[i]->dma_addr = __dma_map(recv_q->work_list[i]->addr, PCN_KMSG_MAX_SIZE, FROM_DEVICE);
		//PCNPRINTK("Inside Recv Buffer: %lx and %llx \n", (unsigned long)recv_q->work_list[i]->addr, recv_q->work_list[i]->dma_addr);
	}

	//index = __get_recv_index(recv_q);
	__update_recv_index(recv_q, 0);

	return recv_q;

out:
	PCNPRINTK("Receive Queue Setup Failed\n");
	return NULL;
}

static __init int __setup_xdma_buffer(void)
{
	int ret, i;
	//dma_addr_t dma_addr;
	//const size_t buffer_size = PCN_KMSG_MAX_SIZE * MAX_RECV_DEPTH;
	const int order = MAX_ORDER - 1;

	__xdma_sink_address = (void *)__get_free_pages(GFP_KERNEL, order);
	if(!__xdma_sink_address) return -EINVAL;

	__xdma_sink_dma_address = __dma_map(__xdma_sink_address, 1 << (PAGE_SHIFT + order), FROM_DEVICE);
	ret = __verify_dma_mapping(__xdma_sink_dma_address);
	if(ret) goto out_free;

	//PCNPRINTK("Buffer Setup: %llx\n", __xdma_sink_dma_address);

	return 0;

out_free:
	free_pages((unsigned long)__xdma_sink_address, order);
	__xdma_sink_address = NULL;
	return ret;
}

static __init int __setup_ring_buffer(void)
{
	int ret;
	int i;

	/*Initialize send ring buffer */

	ret = ring_buffer_init(&xdma_send_buff, "dma_send");
	if(ret) return ret;

	//PCNPRINTK("Ring Buffer Initialized\n");

	for (i = 0; i < xdma_send_buff.nr_chunks; i++) {
		dma_addr_t dma_addr = __dma_map(xdma_send_buff.chunk_start[i], RB_CHUNK_SIZE, TO_DEVICE);
		ret = __verify_dma_mapping(dma_addr);
		if (ret) goto out_unmap;
		xdma_send_buff.dma_addr_base[i] = dma_addr;
	}

	/* Initialize send work request pool */

	for (i = 0; i < MAX_SEND_DEPTH; i++) {
		struct send_work *work;

		work = kzalloc(sizeof(*work), GFP_KERNEL);
		if (!work) {
			ret = -ENOMEM;
			goto out_unmap;
		}
		work->header.type = WORK_TYPE_SEND;

		work->dma_addr = 0;
		work->length = 0;

		work->next = send_work_pool;
		send_work_pool = work;
	}

	/* Initialize the XDMA work pool */
	//PCNPRINTK("Ring Buffer Init Function Done\n");
	__refill_xdma_work(XDMA_SLOTS);
	return 0;

out_unmap:
	while (xdma_work_pool) {
		struct xdma_work *xw = xdma_work_pool;
		xdma_work_pool = xw->next;
		kfree(xw);
	}
	while (send_work_pool) {
		struct send_work *work = send_work_pool;
		send_work_pool = work->next;
		kfree(work);
	}
	for (i = 0; i < xdma_send_buff.nr_chunks; i++) {
		if (xdma_send_buff.dma_addr_base[i]) {
			dma_unmap(xdma_send_buff.dma_addr_base[i], RB_CHUNK_SIZE, TO_DEVICE);
			xdma_send_buff.dma_addr_base[i] = 0;
		}
	}
	return ret;

}

/* Interrupt Handler for monitoring the XDMA reads and writes */

static irqreturn_t xdma_isr(int irq, void *dev_id)
{
	unsigned long read_irq;
	int ret, index, i;
	void *addr;
	read_irq = read_register(xdma_ctl + ch_irq);

	if(read_irq & 0x01) {
		__channel_interrupts_disable(h2c, KMSG);
		//PCNPRINTK("Sent message");
		__process_sent(curr_sw);

	} else if(read_irq & 0x04) {
		
		__channel_interrupts_disable(c2h, KMSG);
		//PCNPRINTK("Received message");
		index = __get_recv_index(recv_queue);
		ret = __process_received(recv_queue->work_list[index]);
		__update_recv_index(recv_queue, index+1);

	} else if(read_irq & 0x02) {
		__channel_interrupts_disable(h2c, PAGE);
		//PCNPRINTK("Sent page");
		__page_sent(curr_xw);
		
	} else if(read_irq & 0x08)	{
		__channel_interrupts_disable(c2h, PAGE);
		//PCNPRINTK("Received Page");
		
	} else {
		PCNPRINTK("Failure in IRQ Disable\n");
		return IRQ_NONE;
	}

	//PCNPRINTK("IRQ Handled\n");
	return IRQ_HANDLED;
}

/* Registering the IRQ Handler */

static int __setup_irq_handler(void)
{
	int ret;
	int irq = pci_dev->irq;

	ret = request_irq(irq, xdma_isr, 0, "PCN_XDMA", (void *)(xdma_isr));
	if(ret) return ret;

	PCNPRINTK("Interrupt Handler Registered Successfully\n");
	return 0;
}

static int __start_handlers(void)
{

	tsk = kthread_run(send_handler, NULL, "Send_Handler");
	if(IS_ERR(tsk)) {
		PCNPRINTK("Error Instantiating Send Handler\n");
		return 1;
	}

	return 0;
}

static void __exit exit_kmsg_xdma(void)
{

	int i;

	PCNPRINTK("Inside Exit\n");

	/* Detach from messaging layer to avoid race conditions */

	pcn_kmsg_set_transport(NULL);

	PCNPRINTK("Transport set to Null\n");

	set_popcorn_node_online(nid, false);

	PCNPRINTK("Node to false\n");
	//Unmap the physical address

	iounmap(xdma_ctl);
	iounmap(xdma_bypass);
	PCNPRINTK("Unmapped ctl and bypass\n");

	free_irq(pci_dev->irq, (void *)(xdma_isr));
	PCNPRINTK("IRQ Freed\n");

	for (i = 0; i < xdma_send_buff.nr_chunks; i++)
	{
		if (xdma_send_buff.dma_addr_base[i]) {
			dma_unmap(xdma_send_buff.dma_addr_base[i], RB_CHUNK_SIZE, TO_DEVICE);
		}
	}

	PCNPRINTK("DMA Unmapped from the Ring Buffer\n");

	while (send_work_pool) {
		struct send_work *work = send_work_pool;
		send_work_pool = work->next;
		kfree(work);
	}
	PCNPRINTK("Destroyed sedn work pool\n");

	ring_buffer_destroy(&xdma_send_buff);
	PCNPRINTK("Destroyed Ring Buff\n");

	free_queue(send_queue);
	free_queue_r(recv_queue);

	PCNPRINTK("Queues freed\n");

	while (xdma_work_pool) {
		struct xdma_work *xw = xdma_work_pool;
		xdma_work_pool = xw->next;
		kfree(xw);
	}
	PCNPRINTK("Destroyed xdma work pool\n");

	free_pages((unsigned long)__xdma_sink_address, MAX_ORDER - 1);
	PCNPRINTK("Free pages from xdma\n");
	dma_unmap(__xdma_sink_dma_address, 1 << (PAGE_SHIFT + MAX_ORDER - 1), FROM_DEVICE);
	PCNPRINTK("Unmapped DMA Buff\n");

	destroy_workqueue(wq);

	if(tsk) {
		kthread_stop(tsk);
		PCNPRINTK("KThread Stopped\n");
	}

	PCNPRINTK("Popcorn message layer over XDMA unloaded\n");
	return;
}

static int __init init_kmsg_xdma(void)
{
	int i, ret;

	PCNPRINTK("\n ... Loading Popcorn messaging Layer over XDMA ...\n");

	pcn_kmsg_set_transport(&transport_xdma);

	pci_dev = pci_get_device(VEND_ID, DEV_ID, NULL);
	if(pci_dev == NULL) goto out;

	pci_dev->dev.coherent_dma_mask = ~0;
	pci_dev->dev.dma_mask = &pci_dev->dev.coherent_dma_mask;
	PCNPRINTK("Found PCIe\n");
	PCNPRINTK("Masks: %lx and %lx and %lx and %lx", MAX_SEND_DEPTH, MAX_RECV_DEPTH, PCN_KMSG_MAX_SIZE, XDMA_SLOTS);

	ret =__config_pcie(pci_dev);
	if(ret){
		goto invalid;
	}

	PCNPRINTK("Configured PCIe\n");

	ctl_address = __pci_map(pci_dev, CTL);
	if(!ctl_address) {
		PCNPRINTK("XDMA Configuration Failed\n");
		goto invalid;
	}

	PCNPRINTK("Mapped PCIe\n");

	bypass_address = __pci_map(pci_dev, BYPASS);
	if(!bypass_address) {
		PCNPRINTK("XDMA Configuration Failed\n");
		goto invalid;
	}

	xdma_ctl = __remap_regions(ctl_address, XDMA_SIZE);
	if(!xdma_ctl) goto invalid;

	xdma_bypass = __remap_regions(bypass_address, BYPASS_SIZE);
	if(!xdma_bypass) goto invalid;

	PCNPRINTK("\n XDMA Layer Configured ...\n");

	my_nid = __get_node_info();
	PCNPRINTK("Node number: %d\n", my_nid);

	set_popcorn_node_online(my_nid, true);

	if(__setup_irq_handler()) {
		goto out_free;
	}
	PCNPRINTK("IRQ Done\n");
	if(__setup_ring_buffer()) {
		goto out_free;
	}
	PCNPRINTK("Ring Buff Done\n");
	if(__setup_xdma_buffer()) {
		goto out_free;
	}
	PCNPRINTK("XDMA Buff Done\n");

	wq = create_workqueue("recv");
	if(!wq) {
		goto out_free;
	}
	PCNPRINTK("Work Queue Done\n");

	send_queue = __setup_send_queue(MAX_SEND_DEPTH);
	if(!send_queue) {
		goto out_free;
	}
	PCNPRINTK("Sent Queue done\n\r");

	recv_queue = __setup_recv_buffer(MAX_RECV_DEPTH);
	if(!recv_queue) {
		goto out_free;
	}
	PCNPRINTK("Receive Queue done\n\r");
	if(__start_handlers()) {
		goto out_free;
	}

	PCNPRINTK("Handlers are setup\n\r");

	broadcast_my_node_info(2);

	PCNPRINTK("... Ready on XDMA ... \n");

	return 0;

out:
	PCNPRINTK("PCIe Device not found!!\n");
	exit_kmsg_xdma();
	return -EINVAL;

invalid:
	PCNPRINTK("DMA Bypass not found!..\n");
	exit_kmsg_xdma();
	return -EINVAL;

out_free:
	PCNPRINTK("Inside Out Free of INIT\n");
	exit_kmsg_xdma();
	return -EINVAL;

}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Naarayanan");
MODULE_DESCRIPTION("XDMA Messaging Layer");

module_param(use_rb_thr, uint, 0644);
MODULE_PARM_DESC(use_rb_thr, "Threshold for using pre-allocated and pre-mapped ring buffer");

module_param_named(features, transport_xdma.features, ulong, 0644);
MODULE_PARM_DESC(use_xdma, "2: FPGA layer to transfer pages");

module_init(init_kmsg_xdma);
module_exit(exit_kmsg_xdma);
