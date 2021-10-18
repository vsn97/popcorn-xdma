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
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/time.h>

#include <popcorn/stat.h>
#include <popcorn/pcn_kmsg.h>
#include <popcorn/page_server.h>
#include <popcorn/pcie.h>
#include "common.h"
#include "ring_buffer.h"


#define MAX_RECV_DEPTH	(((PAGE_SIZE << (MAX_ORDER - 1)) * 4) / PCN_KMSG_MAX_SIZE)
#define MAX_SEND_DEPTH	(MAX_RECV_DEPTH)
#define XDMA_SLOT_SIZE PAGE_SIZE * 2
#define XDMA_SLOTS 320

static unsigned int use_rb_thr = PAGE_SIZE / 2;

unsigned long ctl_address;
unsigned long axi_address;
static int j = 0;
void __iomem *xdma_x;
void __iomem *xdma_c;

/* BAR Addresses of the FPGA PCIe */

static struct pci_dev *pci_dev;

static char *__xdma_sink_address;
static dma_addr_t __xdma_sink_dma_address;
static struct workqueue_struct *wq;
static struct task_struct *tsk;
struct semaphore q_empty;
struct semaphore q_full;

/* Index of Receive Queue */

static int page_ix = 0;
static int nid;

static ktime_t start_s, start_w, end_s, end_w;
s64 actual_time_w, actual_time_s; 

static int KV[XDMA_SLOTS];

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

	PGREAD = 0,
	PGWRITE = 1,
	VMF_CONTINUE = 2,
	PGINVAL = 3,
};

enum {

	KMSG = 0,
	PAGE = 1,
	RPR_RD = 2,
	INVAL = 3,
	FAULT = 4,
	MKWRITE = 5,
	FETCH = 6,
	RPR_WR = 7,
	VMFC = 8,
};

enum {

	AXI = 0,
	CTL = 1,
};

enum {

	FROM_DEVICE = 0,
	TO_DEVICE = 1,
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

struct pcn_work {
	struct work_struct work_q;
	void *addr;
};

struct prot_work {
	struct work_struct work_q;
	int x;
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
static DEFINE_SPINLOCK(send_queue_lock);
static DEFINE_SPINLOCK(xdma_lock);
static DEFINE_SPINLOCK(__xdma_slots_lock);
static DEFINE_SPINLOCK(xdma_work_pool_lock);

static struct ring_buffer xdma_send_buff = {};
static struct send_work *send_work_pool = NULL;

static queue_t *send_queue;
static queue_tr *recv_queue;

static struct xdma_work *xdma_work_pool = NULL;

static void __update_recv_index(queue_tr *q, int i)
{
	
	dma_addr_t dma_addr;
	int ret;
	//void *addr;

	if(i == q->nr_entries)	{
		i = 0;
		q->tail = -1;
	}

	dma_addr = q->work_list[i]->dma_addr;
	//addr = q->work_list[i]->addr;

	ret = config_descriptors_bypass(dma_addr, PCN_KMSG_MAX_SIZE, FROM_DEVICE, KMSG);
	//PCNPRINTK("Updated Recv Index: %llx\n", dma_addr);
}

/*
int queue_empty(queue_t* q)
{
	if (q == NULL){
		return -1;
	} else if(q->size == 0) {
		return 1;
	} else {
		return 0;
	}
}

int queue_full(queue_t* q)
{
	if (q == NULL){
		return -1;
	} else if(q->size == q->nr_entries){
		return 1;
	} else{
		return 0;
	}
}

int queue_emptyr(queue_tr* q)
{
	if (q == NULL){
		return -1;
	} else if(q->size == 0) {
		return 1;
	} else {
		return 0;
	}
}

int queue_full_r(queue_tr* q)
{
	if (q == NULL) {
		return -1;
	} else if(q->size == q->nr_entries) {
		return 1;
	} else {
		return 0;
	}
}
*/

static void __enq_send(struct send_work *work)
{
	int ret;
	do {

		ret = down_interruptible(&q_full);
		if(ret == -EINTR) {
			return -1;
		}
	} while(ret);
	//PCNPRINTK("Inside Enq Send\n\r");
	spin_lock(&send_queue_lock);
	send_queue->tail = (send_queue->tail + 1) % send_queue->nr_entries;
	send_queue->work_list[send_queue->tail] = work;
	send_queue->size++;
	spin_unlock(&send_queue_lock);
	up(&q_empty);
}

static int __get_recv_index(queue_tr *q)
{
	q->tail = (q->tail + 1) % q->nr_entries;
	//PCNPRINTK("Recv Index: %d\n", q->tail);
	return q->tail;
}

/*
static int __xdma_transfer(dma_addr_t dmaAddr, size_t size, int x)
{

	u32 addr_lsb, addr_msb;

	//Mapping the physical address to virtual addresses to perform R/W operations with size

	addr_msb = (u32)((dmaAddr & XDMA_MSB_MASK) >> 32);
	addr_lsb = (u32)(dmaAddr & XDMA_LSB_MASK);

	// KMSGs are sent through Channel 0 and Page data through Channel 1 of XDMA 

	if(!x) {
		write_register(addr_msb, (u32 *)xdma_bypass + 1);
		write_register(addr_lsb, (u32 *)xdma_bypass + 2);
		write_register(size, (u32 *)xdma_bypass + 3);
		//PCNPRINTK("Wrote KMSG: %d and %lx and %lx and %lx\n", x, read_register((u32 *)xdma_bypass + 1), read_register((u32 *)xdma_bypass + 2), read_register((u32 *)xdma_bypass + 3));
	} else {
		write_register(addr_msb, (u32 *)xdma_bypass + 30);
		write_register(addr_lsb, (u32 *)xdma_bypass + 31);
		write_register(size, (u32 *)xdma_bypass + 32);
		//PCNPRINTK("Wrote Page: %d and %lx and %lx and %lx\n", x, read_register((u32 *)xdma_bypass + 30), read_register((u32 *)xdma_bypass + 31), read_register((u32 *)xdma_bypass + 32));
	}

	//PCNPRINTK("Initiating Transfer .... \n");

	return 0;

remap:
	PCNPRINTK("Mapping Failed!..");
	return 1;

}
*/

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


		if(likely(work->addr)) {
			work->dma_addr += sizeof(struct rb_alloc_header);
		} else {
			/* Kmalloc when the ring buffer is full */

			work->addr = kmalloc(sizeof(struct rb_alloc_header) + size, GFP_ATOMIC);

			map_start = work->addr + sizeof(struct rb_alloc_header);

			set_bit(SW_FLAG_FROM_BUFFER, &work->flags);
		}

		rbah = work->addr;
		rbah->work = work;
	} else {
		//PCNPRINTK("Message exists inside the xdma send work map function:%d and %lx\n",
				 //  msg->header.type, msg->header.size);
		work->addr = msg;
		map_start = work->addr;
	}

	if(map_start) {
		int ret;
		work->dma_addr = dma_map_single(&pci_dev->dev,map_start, size, DMA_TO_DEVICE);
		ret = dma_mapping_error(&pci_dev->dev,work->dma_addr);
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
	if (!xdma_work_pool) {

		__refill_xdma_work(XDMA_SLOTS);
	}

	xw->dma_addr = dma_addr;
	xw->addr = addr;
	xw->length = size;
	xw->remote_addr = raddr;
	//PCNPRINTK("XW Contents: %llx and %llx and %llx\n", (unsigned long)addr, dma_addr, raddr);
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
/*
static int __send_sw(struct send_work *work)
{
	int ret, i;
	dma_addr_t dma_addr = work->dma_addr;
	size_t size = work->length;
	unsigned long flags;

	while(read_register((u32 *)xdma_bypass+2));
	curr_sw = work;
	spin_lock(&xdma_lock);
	ret = __xdma_transfer(dma_addr, size, KMSG);
	//PCNPRINTK("Message being sent: %d and %d and %lx\n", msg->header.type, msg->header.from_nid, msg->header.size); 
	spin_unlock(&xdma_lock);
	if(ret) return ret;

	return 0;
}
/*
static int __send_xdma_work(struct xdma_work *xw, size_t size)
{
	int ret;
	PCNPRINTK("Inside the xdma work send function\n");
	dma_addr_t dmaAddr;
	unsigned long flags;
	dmaAddr = xw->dma_addr;
	
	return 0;
}
*/

static void __put_xdma_send_work(struct send_work *work)
{
	unsigned long flags;
	//PCNPRINTK("Put xdma send work\n");

	if(test_bit(SW_FLAG_MAPPED, &work->flags)) {
		dma_unmap_single(&pci_dev->dev,work->dma_addr, work->length, DMA_TO_DEVICE);
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
	struct pcn_kmsg_message *msg;
	int ret, i;
	do {

		ret = down_interruptible(&q_empty);
		if(ret == -EINTR || kthread_should_stop()){
			return 0;
		}
	} while(ret);

	spin_lock(&send_queue_lock);
	work = q->work_list[q->head];
	q->head = (q->head + 1) % q->nr_entries;
	q->size--;
	spin_unlock(&send_queue_lock);
	up(&q_full);
	msg = (struct pcn_kmsg_message *)(work->addr + sizeof(struct rb_alloc_header));
	//PCNPRINTK("__SEND FRAME __\n");
	//for(i = 0; i < 25; i++){
		//PCNPRINTK("%lx\n", read_register((u32 *)msg+i));
	//}
	//PCNPRINTK("__SEND FRAME END __\n");
	curr_sw = work;
	ret = config_descriptors_bypass(work->dma_addr, work->length, TO_DEVICE, KMSG);
	ret = xdma_transfer(TO_DEVICE, KMSG);

	if(ret) goto out;

	return 0;

out:
	PCNPRINTK("Sending KMSG Failed!\n");
	return 1;
}

/* To send kernel messages to the other node */

int xdma_kmsg_send(int nid, struct pcn_kmsg_message *msg, size_t size)
{
	struct send_work *work;
	int ret, i;
	DECLARE_COMPLETION_ONSTACK(done);

	//PCNPRINTK("Inside xdma send function and size: %d and %d and %lx\n", msg->header.type, msg->header.from_nid, msg->header.size);

	if(size <= use_rb_thr) {
		work = __get_xdma_send_work(size);
		memcpy(work->addr + sizeof(struct rb_alloc_header), msg, size);
	} else {
		work = __get_xdma_send_work_map(msg, size);
	}

	//PCNPRINTK("__SEND FRAME __\n");
	//for(i = 0; i < 25; i++){
	//	printk("%lx\n", read_register((u32 *)msg+i));
	//}
	//PCNPRINTK("__SEND FRAME END __\n");

	work->done = &done;
	__enq_send(work);

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

	//DECLARE_COMPLETION_ONSTACK(done);
	struct xdma_work *xw;
	dma_addr_t dma_addr;
	int ret;

	//PCNPRINTK("Inside xdma write function\n");

	dma_addr = dma_map_single(&pci_dev->dev,addr, size, DMA_TO_DEVICE);
	ret = dma_mapping_error(&pci_dev->dev,dma_addr);

	if(!((u32)(dma_addr & XDMA_LSB_MASK))) {
		dma_addr = dma_map_single(&pci_dev->dev,addr, size, DMA_TO_DEVICE);
		ret = dma_mapping_error(&pci_dev->dev,dma_addr);
	}

	//PCNPRINTK("Done mapping Page: %llx\n", dma_addr);

	BUG_ON(ret);

	xw = __get_xdma_work(dma_addr, addr, size, raddr);
	BUG_ON(!xw);
	//PCNPRINTK("Got the xdma work\n");
	//xw->done = &done;
	//PCNPRINTK("Page to be sent: %llx \n", xw->dma_addr);
	//curr_xw = xw;
	ret = config_descriptors_bypass(xw->dma_addr, size, TO_DEVICE, PAGE);
	ret = xdma_transfer(TO_DEVICE, PAGE);
	if(ret) {
		PCNPRINTK("Cannot do XDMA KMSG write\n");
		goto out;
	}

	/* if(!try_wait_for_completion(&done)) {
		wait_for_completion(&done);
	}*/
	//PCNPRINTK("Page Write done\n");

out:
	dma_unmap_single(&pci_dev->dev,dma_addr, size, DMA_TO_DEVICE);
	__put_xdma_work(xw);
	return ret;
}

int xdma_kmsg_post(int nid, struct pcn_kmsg_message *msg, size_t size)
{
	struct rb_alloc_header *rbah = (struct rb_alloc_header *)msg - 1;
	struct send_work *work = rbah->work;

	//PCNPRINTK("Contents inside the POST function: %d and %d and %lx\n", msg->header.type, msg->header.from_nid, msg->header.size);
	//PCNPRINTK("__POST FRAME __\n");
	//for(i = 0; i < 25; i++){
	//	printk("%lx\n", read_register((u32 *)msg+i));
	//}
	//PCNPRINTK("__POST FRAME END __\n");
	__enq_send(work);

	return 0;
}

void xdma_kmsg_put(struct pcn_kmsg_message *msg)
{
	struct rb_alloc_header *rbah = (struct rb_alloc_header *)msg - 1;
	struct send_work *work = rbah->work;
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

void xdma_kmsg_done(struct pcn_kmsg_message *msg)
{
	//PCNPRINTK("xdma_kmsg_done\n");
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
			i = deq_send(send_queue);
			if(i) {
				printk(KERN_ERR "Error sending message\n");
			}
		}

	return 0;
}

unsigned int queue_size(queue_t* q)
{
	if (q == NULL){
		return - 1;
	} else {
		return q->size;
	}
}

void free_queue(queue_t* q)
{
	int i;
	for(i = 0; i<q->size; i++) {
		kfree(q->work_list[i]);
	}

	kfree(q->work_list);
	kfree(q);
}

void free_queue_r(queue_tr* q)
{
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

static void __update_xdma_index(dma_addr_t dma_addr, size_t size)
{
	config_descriptors_bypass(dma_addr, size, FROM_DEVICE, PAGE);
	//write_register(size, (u32 *)xdma_bypass + 22);
	//PCNPRINTK("Updated XDMA Index: %llx\n", read_register((u32 *)xdma_bypass + 21));
}

static int __check_page_index(int i)
{
	if(i == XDMA_SLOTS) {
		if(KV[0] == 0) {
			//PCNPRINTK("Page index updated\n");
			page_ix = 0;
			return page_ix;
		} else {
			PCNPRINTK("Receive Buffer Full\n\r");
			while(KV[0] != 0);
			page_ix = 0;
			return 0;
		}
	} else if(KV[i]) {
		PCNPRINTK("Buffer not unpinned: %d\n\r", KV[i]);
		return -1;
	} else {
		return i;
	}
}

struct pcn_kmsg_xdma_handle *xdma_kmsg_pin_buffer(void *msg, size_t size)
{
	int ret;
	struct pcn_kmsg_xdma_handle *xh = kmalloc(sizeof(*xh), GFP_KERNEL);
	//PCNPRINTK("Inside the Pin Buffer function\n");
	spin_lock(&__xdma_slots_lock);
	ret = __check_page_index(page_ix);
	if(ret < 0) {
		PCNPRINTK("Error in the KV\n");
		return NULL;
	}

	xh->addr = __xdma_sink_address + XDMA_SLOT_SIZE * page_ix;
	xh->dma_addr =	__xdma_sink_dma_address + XDMA_SLOT_SIZE * page_ix;
	xh->flags = page_ix;
	KV[page_ix] = 1;
	__update_xdma_index(xh->dma_addr, PAGE_SIZE);
	page_ix += 1;
	//PCNPRINTK("Pin Index and DMA Address: %d and %llx\n", page_ix, xh->dma_addr);
	spin_unlock(&__xdma_slots_lock);
	return xh;
}

void xdma_kmsg_unpin_buffer(struct pcn_kmsg_xdma_handle *handle)
{
	spin_lock(&__xdma_slots_lock);
	BUG_ON(!(KV[handle->flags]));
	KV[handle->flags] = 0;
	//PCNPRINTK("Unpinned buffer: %d and %d\n", handle->flags, KV[handle->flags]);
	spin_unlock(&__xdma_slots_lock);
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

/*
static u32 __get_node_info(void)
{
	u32 ret;

	ret = ioread32((u32 *)xdma_bypass);
	return ret;
}
*/

static void process_msg(struct work_struct *work)
{

	struct pcn_kmsg_message *msg;
	int i;
	struct pcn_work *rw = (struct pcn_work *)work;
	msg = rw->addr;
	//PCNPRINTK("Sending message to process: %d and %d and %lx and %llx\n", msg->header.from_nid, msg->header.type, msg->header.size, (unsigned long)rw->addr);
	//PCNPRINTK("__MSG FRAME __\n");
	//for(i = 0; i < 25; i++){
		//PCNPRINTK("%lx\n", read_register((u32 *)msg+i));
	//}
	//PCNPRINTK("__MSG FRAME END __\n");
	pcn_kmsg_process(msg);
	
	kfree((void *)work);

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
	struct pcn_kmsg_message *msg;
	struct pcn_work *work;
	//void *addr;
	bool ret;
	int i;

	msg = rws->addr;
	if(msg->header.type < 0 || msg->header.type >= PCN_KMSG_TYPE_MAX || 
	 msg->header.size < 0 || msg->header.size > PCN_KMSG_MAX_SIZE){
		printk(KERN_ERR "------- Faulty Work Rejected -----------!!\n");
		return 0;
	}
	
	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	//PCNPRINTK("Message Received: %d and %d and %lx and %llx\n", msg->header.from_nid, msg->header.type, msg->header.size, (unsigned long)rws->addr);
	//PCNPRINTK("__RECV FRAME __\n");
	//for(i = 0; i < 25; i++){
		//PCNPRINTK("%lx\n", read_register((u32 *)msg+i));
	//}
	//PCNPRINTK("__RECV FRAME END __\n");

	INIT_WORK((struct work_struct *)work, process_msg);
	work->addr = rws->addr;
	ret = queue_work(wq, (struct work_struct *)work);
	//PCNPRINTK("Queued Work\n");

	if(ret == false) {
		PCNPRINTK("Work already exists\n");
		return 1;
	}

	return 0;
}

static void prot_handle_rpr(struct work_struct *work)
{
	int x;
	struct prot_work *pw = (struct prot_work *)work;
	x = pw->x;
	//PCNPRINTK("Inside the prot_proc_handle func Work: %d\n", x);
	prot_proc_handle_rpr(x);
	kfree((void *)work);
}

static void prot_handle_inval(struct work_struct *work)
{
	//struct prot_work *pw = (struct prot_work *)work;
	//PCNPRINTK("Inval Intr\n");
	prot_proc_handle_inval();
	kfree((void *)work);
}


static void __prot_proc_recv(int x)
{

	struct prot_work *work;
	int ret;

	//PCNPRINTK("Inside the prot_proc_recv Work: %d\n", x);
	work = kmalloc(sizeof(*work), GFP_ATOMIC);

	if(x == PGINVAL) {
		//PCNPRINTK("Queueing inval work\n");
		INIT_WORK((struct work_struct *)work, prot_handle_inval);
		work->x = x;
		ret = queue_work(wq, (struct work_struct *)work);
	} else {
		//PCNPRINTK("Queueing rpr work\n");
		INIT_WORK((struct work_struct *)work, prot_handle_rpr);
		work->x = x;
		ret = queue_work(wq, (struct work_struct *)work);
	}

	//PCNPRINTK("Queued Work\n");
	if(ret == false) {
		PCNPRINTK("Work already exists\n");
	}
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
		recv_q->work_list[i]->dma_addr = dma_map_single(&pci_dev->dev,recv_q->work_list[i]->addr, PCN_KMSG_MAX_SIZE, DMA_FROM_DEVICE);
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

	__xdma_sink_dma_address = dma_map_single(&pci_dev->dev,__xdma_sink_address, 1 << (PAGE_SHIFT + order), DMA_FROM_DEVICE);
	ret = dma_mapping_error(&pci_dev->dev,__xdma_sink_dma_address);
	if(ret) goto out_free;

	//PCNPRINTK("Buffer Setup: %llx\n", __xdma_sink_dma_address);

	//__update_xdma_index(__xdma_sink_dma_address + XDMA_SLOT_SIZE * page_ix, PAGE_SIZE);
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

	PCNPRINTK("Ring Buffer Initialized\n");

	for (i = 0; i < xdma_send_buff.nr_chunks; i++) {
		dma_addr_t dma_addr = dma_map_single(&pci_dev->dev,xdma_send_buff.chunk_start[i], RB_CHUNK_SIZE, DMA_TO_DEVICE);
		ret = dma_mapping_error(&pci_dev->dev,dma_addr);
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
	PCNPRINTK("Ring Buffer Init Function Done\n");
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
			dma_unmap_single(&pci_dev->dev,xdma_send_buff.dma_addr_base[i], RB_CHUNK_SIZE, DMA_TO_DEVICE);
			xdma_send_buff.dma_addr_base[i] = 0;
		}
	}
	return ret;

}

/* Interrupt Handler for monitoring the XDMA reads and writes */

static irqreturn_t xdma_isr(int irq, void *dev_id)
{
	unsigned long read_ch_irq, read_usr_irq, pkey, addr;
	int ret, index, recv_i, ws_id;
	
	read_ch_irq = read_register(xdma_c + ch_irq);
	read_usr_irq = read_register(xdma_c + usr_irq);
	
	if(read_usr_irq & 0x02) {
		//PCNPRINTK("Received Page in FIFO: %x\n", read_usr_irq);
		user_interrupts_disable(PAGE);
		ret = xdma_transfer(FROM_DEVICE, PAGE);
		user_interrupts_enable(PAGE);
		//PCNPRINTK("Transfer done\n");
		//return IRQ_HANDLED;

	} else if(read_ch_irq & 0x01) {
		channel_interrupts_disable(TO_DEVICE, KMSG);
		__process_sent(curr_sw);
		channel_interrupts_enable(TO_DEVICE, KMSG);
		//PCNPRINTK("Sent message: %x\n", read_ch_irq);		
		//return IRQ_HANDLED;

	} else if(read_ch_irq & 0x04) {

		channel_interrupts_disable(FROM_DEVICE, KMSG);
		recv_i = recv_queue->size;
		ret = __process_received(recv_queue->work_list[recv_i]);
		recv_queue->size += 1;
		if(recv_queue->size == recv_queue->nr_entries) {
			recv_queue->size = 0;
		}
		channel_interrupts_enable(FROM_DEVICE, KMSG);

		//return IRQ_HANDLED;
		PCNPRINTK("Received message: %x\n", read_ch_irq);
	
	} else if(read_ch_irq & 0x02) {
		channel_interrupts_disable(TO_DEVICE, PAGE);
		//__page_sent(curr_xw);
		channel_interrupts_enable(TO_DEVICE, PAGE);
		//PCNPRINTK("Sent page: %x\n", read_ch_irq);	
		//return IRQ_HANDLED;
		
	} else if(read_ch_irq & 0x08) {
		channel_interrupts_disable(FROM_DEVICE, PAGE);
		channel_interrupts_enable(FROM_DEVICE, PAGE);
		//PCNPRINTK("Received Page: %x\n", read_ch_irq);
		//return IRQ_HANDLED;
		
	} else if(read_usr_irq & 0x01) {
		//PCNPRINTK("Received in FIFO: %x\n", read_usr_irq);
		user_interrupts_disable(KMSG);
		ret = xdma_transfer(FROM_DEVICE, KMSG);
		//PCNPRINTK("Transfer done\n");
		index = __get_recv_index(recv_queue);
		__update_recv_index(recv_queue, index + 1);
		user_interrupts_enable(KMSG);
		//return IRQ_HANDLED;

	} else if(read_usr_irq & 0x04) {
		user_interrupts_disable(RPR_RD);
		PCNPRINTK("RPR RD Intr: %x\n", read_usr_irq);
		__prot_proc_recv(PGREAD);
		user_interrupts_enable(RPR_RD);
		//return IRQ_HANDLED;

	} else if(read_usr_irq & 0x08) {	       
		user_interrupts_disable(INVAL);
		 PCNPRINTK("Inval intr: %x\n", read_usr_irq);
		 __prot_proc_recv(PGINVAL);
		user_interrupts_enable(INVAL);
		//return IRQ_HANDLED;

	} else if(read_usr_irq & 0x10) {
		user_interrupts_disable(FAULT);
		printk(KERN_ERR "FAULT intr: %x\n", read_usr_irq);
		PCNPRINTK("PKEY: %lx and %lx\n", ioread32((u32 *)(xdma_x + wr_pkey_msb)), ioread32((u32 *)(xdma_x + wr_pkey_lsb)));
		user_interrupts_enable(FAULT);
		//return IRQ_HANDLED;

	} /* else if(read_usr_irq & 0x20) {
		user_interrupts_disable(MKWRITE);
		//PCNPRINTK("MKWRITE intr: %x\n", read_usr_irq);
		//ws_id = (int)ioread32((u32 *)(xdma_x + proc_ws_id));
		//PCNPRINTK("WS ID: %d\n", ws_id);
		//resolve_waiting(ws_id);
		user_interrupts_enable(MKWRITE);
		//return IRQ_HANDLED;

	} else if(read_usr_irq & 0x40) {
		user_interrupts_disable(FETCH);
		//PCNPRINTK("Fetch intr: %x\n", read_usr_irq);
		//pkey = ((unsigned long) ioread32((u32 *)(xdma_x + wr_pkey_msb)) << 32 | ioread32((u32 *)(xdma_x + wr_pkey_lsb)));
		//addr = ((unsigned long) ioread32((u32 *)(xdma_x + proc_vaddr_msb)) << 32 | ioread32((u32 *)(xdma_x + proc_vaddr_lsb)));
		//update_pkey(pkey, addr);
		user_interrupts_enable(FETCH);
		//return IRQ_HANDLED;

	}*/ else if(read_usr_irq & 0x20) {
		user_interrupts_disable(RPR_WR);
		PCNPRINTK("RPR Wr intr: %x\n", read_usr_irq);
		__prot_proc_recv(PGWRITE);
		user_interrupts_enable(RPR_WR);
		//return IRQ_HANDLED;

	}  else if(read_usr_irq & 0x40) {
		user_interrupts_disable(VMFC);
		PCNPRINTK("VMF Continue intr: %x\n", read_usr_irq);
		__prot_proc_recv(VMF_CONTINUE);
		user_interrupts_enable(VMFC);
		//return IRQ_HANDLED;

	} else {
		PCNPRINTK("Other interrupts: %d and %d\n", read_ch_irq, read_usr_irq);
		//return IRQ_HANDLED;
	}
	
	return IRQ_HANDLED;
}

/* Registering the IRQ Handler */

static int __setup_irq_handler(void)
{
	int ret;
	int irq = pci_dev->irq;

	ret = request_irq(irq, xdma_isr, IRQF_TRIGGER_RISING, "PCN_XDMA", (void *)(xdma_isr));
	if(ret) return ret;

	//PCNPRINTK("Interrupt Handler Registered Successfully\n");
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

	iounmap(xdma_c);
	iounmap(xdma_x);
	PCNPRINTK("Unmapped ctl and bypass\n");

	free_irq(pci_dev->irq, (void *)(xdma_isr));
	PCNPRINTK("IRQ Freed\n");

	for (i = 0; i < xdma_send_buff.nr_chunks; i++)
	{
		if (xdma_send_buff.dma_addr_base[i]) {
			dma_unmap_single(&pci_dev->dev,xdma_send_buff.dma_addr_base[i], RB_CHUNK_SIZE, DMA_TO_DEVICE);
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
	dma_unmap_single(&pci_dev->dev,__xdma_sink_dma_address, 1 << (PAGE_SHIFT + MAX_ORDER - 1), DMA_FROM_DEVICE);
	PCNPRINTK("Unmapped DMA Buff\n");

	destroy_workqueue(wq);
	//delete_pkeys();
	
	if(tsk) {
		wake_up_process(tsk);
		//kthread_stop(tsk);
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

	PCNPRINTK("Masks: %lx and %lx and %lx and %lx", MAX_SEND_DEPTH, MAX_RECV_DEPTH, PCN_KMSG_MAX_SIZE, XDMA_SLOTS);

	ret =__config_pcie(pci_dev);
	if(ret){
		goto invalid;
	}


	ctl_address = __pci_map(pci_dev, CTL);
	if(!ctl_address) {
		PCNPRINTK("XDMA Configuration Failed\n");
		goto invalid;
	}

	PCNPRINTK("Mapped PCIe\n");

	axi_address = __pci_map(pci_dev, AXI);
	if(!axi_address) {
		PCNPRINTK("XDMA Configuration Failed\n");
		goto invalid;
	}
	PCNPRINTK("Addresses: %llx and %llx\n", axi_address, ctl_address);
	xdma_c = ioremap(ctl_address, XDMA_SIZE);
	if(!xdma_c) goto invalid;

	xdma_x = ioremap(axi_address, AXI_SIZE);
	if(!xdma_x) goto invalid;

	PCNPRINTK("Configured PCIe\n");

	ret = init_pcie_xdma(pci_dev, xdma_c, xdma_x);
	if(ret) {
		goto invalid;
	}
	
	PCNPRINTK("\n XDMA Layer Configured ...\n");

	my_nid = 1;
	PCNPRINTK("Node number: %d\n", my_nid);
	write_mynid(my_nid);
	
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

	memset(KV, 0, XDMA_SLOTS * sizeof(int));
	sema_init(&q_empty, 0);
	sema_init(&q_full, MAX_SEND_DEPTH);

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

