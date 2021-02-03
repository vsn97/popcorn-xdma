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
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <rdma/rdma_cm.h>
#include <linux/seq_file.h>

#include <popcorn/stat.h>
#include <popcorn/pcn_kmsg.h>

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
#define XDMA_SLOTS ((PAGE_SIZE << (MAX_ORDER - 1)) / XDMA_SLOT_SIZE)

static unsigned int use_rb_thr = PAGE_SIZE / 2;


/* BAR Addresses of the FPGA PCIe */

static unsigned long ctl_address; 
static unsigned long bypass_address;

/* XDMA Register Offsets */

#define h2c_ctl 0x04
#define c2h_ctl 0x1004
#define h2c_stat 0x44
#define c2h_stat 0x1044

#define ch_irq 0x2044
#define irq_mask 0x2018
#define irq_enable 0x2014

static struct pci_dev *pci_dev;
static void __iomem *xdma_bypass;
static void __iomem *xdma_ctl;
static char *__xdma_sink_address;

/*
static struct device dma_dev = {
	.init_name = "dma_dev",
	.coherent_dma_mask = 
}
*/

struct work_hdr
{
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

/* Send Buffer */

struct sw 
{
  struct work_hdr header;
  void *addr;
  u64 dma_addr;
  u32 length;
  struct sw *next;
  struct completion *done;
  unsigned long flags;
};

/* Receive Buffer */

struct rw 
{
  struct work_hdr header;
  void *addr;
  u32 length;
  dma_addr_t dma_addr;
};

/* XDMA Global Work Buffer */

struct xdma_work
 {

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

 struct rb_alloc_header{
 	struct xdma_work *work;
 	unsigned int flags;
 	unsigned int magic;

 };

const unsigned int rb_alloc_header_magic = 0xbad7face;

static DEFINE_SPINLOCK(send_work_pool_lock);
static struct ring_buffer xdma_send_buff = {};
static struct xdma_work *send_work_pool = NULL;

static DEFINE_SPINLOCK(xdma_work_pool_lock);
static struct xdma_work *xdma_work_pool = NULL;


static void __write_register(void *iomem, u32 value)
{
	iowrite32(iomem, value);
}

static void __read_register(void *iomem)
{
	return ioread32(iomem);
}

/* Converting the kernel virtual address to a dma capable physical address - Replacing ib_dma_map_single()-rdma.c function */

static u64 __dma_map(void *addr, size_t size, int x)
{
	if(!x)
	{
		return dma_map_single(pci_dev->dev, addr, size, DMA_TO_DEVICE);	
	}
	else
	{
		return dma_map_single(pci_dev->dev, addr, size, DMA_FROM_DEVICE);	
	}
	
}

/* DMA Mapping Error verification */

static int __verify_dma_mapping(u64 dma_addr)
{
	return dma_mapping_error(pci_dev->dev, dma_addr);
}

/* DMA Unmapping */

static void dma_unmap(u64 dma_addr, size_t size, int y)
{
	if(!y)
	{
		dma_unmap_single(pci_dev->dev, dma_addr, size, DMA_TO_DEVICE);
	}
	else
	{
		dma_unmap_single(pci_dev->dev, dma_addr, size, DMA_FROM_DEVICE);
	}
	
}

/* Remapping the kernel physical regions to a kernel virtual address to perform R/W operations */

static void __iomem *__remap_regions(unsigned long address, size_t size)
{
  return ioremap(address, size);
}
  
static int __xdma_transfer(dma_addr_t dmaAddr, size_t size)
{

   u32 addr_lsb, addr_msb;

  //Mapping the physical address to virtual addresses to perform R/W operations with size

  p = ioremap(bar_address, size);
  if(p == NULL)
  {
     goto remap;
  }
  addr_msb = (u32)((dmaAddr & XDMA_MSB_MASK) >> 32);
  addr_lsb = (u32)(dmaAddr & XDMA_LSB_MASK);

  printk("MSB and LSB : %lx and %lx\n", addr_msb, addr_lsb);

  iowrite32(addr_lsb, (u32 *)p);
  iowrite32(addr_msb, (u32 *)p + 1);
  iowrite32(size, (u32 *)p + 2);
  printk(KERN_INFO "Contents: %x\n", ioread32((u64 *)p));
  printk(KERN_INFO "\n Initiating Transfer .... \n");

  return 0;

  remap:
        printk(KERN_ERR "Mapping Failed!..");
        return 1;

}

static struct xdma_work *__get_xdma_send_work_map(struct pcn_kmsg_message *msg, size_t size)
{
  unsigned long flags;
  struct xdma_work *work;
  void *map_start = NULL;

  spin_lock_irqsave(&send_work_pool_lock, flags);
  work = send_work_pool;
  send_work_pool = work->next;
  spin_unlock_irqrestore(&send_work_pool_lock, flags);

  work->done = NULL;
  work->flags = 0;

  if(!msg)
  {
  	struct rb_alloc_header *rbah;
  	work->addr = ring_buffer_get_mapped(&xdma_send_buff, sizeof(struct rb_alloc_header) + size, work->dma_addr);

  	if(likely(work->addr)) 
  	{
  		work->dma_addr += sizeof(struct rb_alloc_header);
  	}
  	else
  	{
  		/* Kmalloc when the ring buffer is full */
  		if(WARN_ON_ONCE("ring buffer is full"))
  		{
  			printk(KERN_WARNING "Ring Buffer Utilization: %lu\n", ring_buffer_usage(&xdma_send_buff));
  		}

  	work->addr = kmalloc(sizeof(struct rb_alloc_header) + size, GFP_ATOMIC);

  	map_start = work->addr + sizeof(struct rb_alloc_header);

  	set_bit(SW_FLAG_FROM_BUFFER, &work->flags);
  	}

  	rbah = work->addr;
  	rbah->work = work;
  }

  else
  {
	work->addr = msg;
  	map_start = work->addr;
  }

  if(map_start)
  {
  	int ret;
  	work->dma_addr = __dma_map(map_start, size, TO_DEVICE);
  	ret = __verify_dma_mapping(work->dma_addr);
  	BUG_ON(ret);
  	set_bit(SW_FLAG_MAPPED, &work->flags);

  }
  work->length = size;
  return work;
}

static struct xdma_work *__get_xdma_send_work(size_t size)
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

	for (i = 0; i < xdma_slot; i++) {
		struct xdma_work *xw;

		xw = kzalloc(sizeof(*xw), GFP_KERNEL);
		if (!xw) goto out;

		xw->header.type = WORK_TYPE_XDMA;

		xw->remote_addr = 0;
		xw->addr = 0;
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

static struct xdma_work *__get_xdma_work(dma_addr_t dma_addr, size_t size, dma_addr_t raddr)
{
  struct xdma_work *xw;

  spin_lock(&xdma_work_pool_lock);
  xw = xdma_work_pool;
  xdma_work_pool = xdma_work_pool->next;
  spin_unlock(&xdma_work_pool_lock);

	if (!xdma_work_pool) {
		__refill_xdma_work(XDMA_SLOTS);
	}

  xw->addr = dma_addr;
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

static int __send_sw(struct sw *work, size_t size)
{	
	int ret;
	dma_addr_t dma_addr = work->dma_addr;
	size_t length = size;

	ret = __xdma_transfer(dma_addr, length);
	if(ret) return ret;

	return 0;
}

static int __send_xdma_work(struct xdma_work *work, size_t size)
{ 
  int ret;
  unsigned long addr_lsb, addr_msb;
  dma_addr_t dmaAddr;
  dmaAddr = work->addr;

  ret = __xdma_transfer(dmaAddr, size);
  if(ret) return ret;

 return 0;
}

static void __put_xdma_send_work(struct sw *work)
{
	unsigned long flags;
	if(test_bit(SW_FLAG_MAPPED, &work->flags))
	{
		dma_unmap(work->dma_addr, work->length, TO_DEVICE);
	}
	if(test_bit(SW_FLAG_FROM_BUFFER, &work->flags))
	{
		if(unlikely(test_bit(SW_FLAG_MAPPED, &work->flags)))
		{
			kfree(work->addr);
		}
		else
		{
			ring_buffer_put(&xdma_send_buff, work->addr);
		}
	}

	spin_lock_irqsave(&send_work_pool_lock, flags);
	work->next = send_work_pool;
	send_work_pool = work;
	spin_unlock_irqrestore(&send_work_pool_lock, flags);

}

/* To send kernel messages to the other node */

int xdma_kmsg_send(int nid, struct pcn_kmsg_message *msg, size_t size)
{
  struct sw *work;
  int ret;
  DECLARE_COMPLETION_ONSTACK(done);

  if(size <= use_rb_thr) 
  {
  	work = __get_xdma_send_work(size);
  	memcpy(work->addr + sizeof(struct rb_alloc_header), msg, size);
  }
  else
  {
  	work = __get_xdma_send_work_map(msg, size);
  }
  

  work->done = &done;


  ret = __send_sw(work, size);

  if(ret) goto out;

  if(!try_wait_for_completion(&done)){
  	ret = wait_for_completion_io_timeout(&done, 60 *HZ);
  	if(!ret)
  	{
  		ret = -ETIME;
  		goto out;
  	}
  }
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

  dma_addr = __dma_map(addr, size, TO_DEVICE);
  ret = __verify_dma_mapping(dma_addr);
  BUG_ON(ret);

  xw = __get_xdma_work(dma_addr, size, raddr);
  BUG_ON(!xw);

  xw->done = &done;

  ret = __send_xdma_work(xw, size);
  if(ret) 
  {
    printk("Cannot do XDMA KMSG write");
    goto out;
  }

  if(!try_wait_for_completion(&done)) {
  	wait_for_completion(&done);
  }

out:
  dma_unmap(dma_addr, size, TO_DEVICE);
  __put_xdma_work(xw);
  return ret;
}

int xdma_kmsg_post(int nid, struct pcn_kmsg_message *msg, size_t size)
{
	struct rb_alloc_header *rbah = (struct rb_alloc_header *)msg - 1;
	struct sw *work = rbah->work;
	int ret;

	ret = __xdma_transfer(work->dma_addr, size);
	if(ret)
	{
		__put_xdma_send_work(work);
		return ret;
	}

	return 0;
}

void xdma_kmsg_put(struct pcn_kmsg_message *msg)
{
	struct rb_alloc_header *rbah = (struct rb_alloc_header *)msg - 1;
	struct sw *work = rbah->work;
	__put_xdma_send_work(work);
}

static int __config_pcie(struct pci_dev *dev)
{
  int ret;
  ret =  pci_dev_put(pci_dev);
  if(ret) return ret;
  
  ret = pci_enable_device(pci_dev);
  if(ret) return ret;

  return 0;
}

static unsigned long __pci_map(struct pci_dev *dev, int BAR)
{
  unsigned long addr;

  addr = pci_resource_start(pci_dev, BAR);
  if(!addr)
  {
    return 0;
  }

  return addr;
}

void xdma_kmsg_done(struct pcn_kmsg_message *msg)
{
	kfree(msg);
}

struct pcn_kmsg_message *xdma_kmsg_get(size_t size)
{
	struct sw *work = __get_xdma_send_work(size);
	struct rb_alloc_header *rbah = work->addr;

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


struct pcn_kmsg_transport transport_xdma = {
	.name = "xdma",
	.features = PCN_KMSG_FEATURE_XDMA,

	.get = xdma_kmsg_get,
	.put = xdma_kmsg_put,
	.stat = xdma_kmsg_stat,

	.post = xdma_kmsg_post,
	.send = xdma_kmsg_send,
	.done = xdma_kmsg_done,

  	.xdma_write = xdma_kmsg_write,
  	.xdma_read = xdma_kmsg_read,

};

static u32 __get_node_info(unsigned long addr, size_t size)
{
	u32 ret;

	ret = ioread32((u32 *)xdma_bypass);
	return ret;
}

static void __channel_interrupts_disable(int z)
{
  if(z)
    {
      write_register((u32 *)(xdma_ctl + h2c_ctl), 0x00);
      read_register((u32 *)(xdma_ctl + h2c_stat));
      write_register((u32 *)(xdma_ctl + irq_mask), 0x01);
      write_register((u32 *)(xdma + irq_enable), 0x01);
    }
  else
    {
      write_register((u32 *)(xdma_ctl + c2h_ctl), 0x00);
      read_register((u32 *)(xdma_ctl + c2h_stat));
      write_register((u32 *)(xdma_ctl + irq_mask), 0x01);
      write_register((u32 *)(xdma + irq_enable), 0x01);
    } 
}

static void __process_msg(struct xdma_work *xw)
{
  pcn_kmsg_process(xw->addr);
}	

static void __process_received(void)
{
  struct xdma_work *xw = (struct xdma_work *)sink_buffer;
  if(!xw)
  {
  	goto out;
  }
  switch(xw->header.type) {
  	case WORK_TYPE_SEND:
  		__process_msg(&xw);
  		break;
  	case WORK_TYPE_RECV:
  	case WORK_TYPE_XDMA:

  	default:
  			printk("Unknown completion\n");
  }

 out:
 	printk("Process receive mapping failed\n");
}

static __init int __setup_recv_buffer(void)
{
	int ret, i;
	dma_addr_t dma_addr;
	const size_t buffer_size = PCN_KMSG_MAX_SIZE * MAX_RECV_DEPTH;
	const int order = MAX_ORDER - 1;

	__xdma_sink_address = (void *)__get_free_pages(GFP_KERNEL, order);
	if(!__xdma_sink_address) return -EINVAL;

	__xdma_sink_address = __dma_map(__xdma_sink_address, 1 << (PAGE_SHIFT + order), FROM_DEVICE);
	ret = __verify_dma_mapping(__xdma_sink_address);
	if(ret) goto out_free;

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

	for (i = 0; i < xdma_send_buff.nr_chunks; i++) 
	{
		dma_addr_t dma_addr = __dma_map(xdma_send_buff.chunk_start[i], RB_CHUNK_SIZE, TO_DEVICE);
		ret = __verify_dma_mapping(dma_addr);
		if (ret) goto out_unmap;
		xdma_send_buff.dma_addr_base[i] = dma_addr;
	}

	/* Initialize send work request pool */

	for (i = 0; i < MAX_SEND_DEPTH; i++) 
	{
		struct sw *work;

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

	__refill_xdma_work(XDMA_SLOTS);
	return 0;	

out_unmap:
	while (xdma_work_pool) 
	{
		struct xdma_work *xw = xdma_work_pool;
		xdma_work_pool = xw->next;
		kfree(xw);
	}
	while (send_work_pool) 
	{
		struct sw *work = send_work_pool;
		send_work_pool = work->next;
		kfree(work);
	}
	for (i = 0; i < xdma_send_buff.nr_chunks; i++) 
	{
		if (xdma_send_buff.dma_addr_base[i]) 
		{
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
  
  read_irq = read_register(intr);
    
  if(read_irq == 0x01)
  {
    __channel_interrupts_disable(h2c);
  }
  else if(read_irq == 0x02)
  {
    __channel_interrupts_disable(c2h);
    __process_received();
  }

  return IRQ_HANDLED;
}

/* Registering the IRQ Handler */

static int __setup_xdma_handler(void)
{
  int ret;
  int irq = pci_dev->irq;

  ret = request_irq(irq, xdma_isr, 0, "PCN_XDMA", (void *)(xdma_isr));
  if(ret) return ret;

  return 0;
}  

static void __exit exit_kmsg_xdma(void)
{

  int nid;
  int i;

  /* Detach from messaging layer to avoid race conditions */

  pcn_kmsg_set_transport(NULL);

  set_popcorn_node_online(nid, false);

  iowrite32(0x00000000, (u32 *)p);
  iowrite32(0x00000000, (u32 *)p + 1);
  printk(KERN_INFO "Contents: %x\n", ioread32((u64 *)p));
  
  //Unmap the physical address
     
  iounmap(p);

  free_irq(pci_dev->irq, (void *)(xdma_isr));

  for (i = 0; i < xdma_send_buff.nr_chunks; i++) 
  {
		if (xdma_send_buff.dma_addr_base[i]) {
			dma_unmap(xdma_send_buff.dma_addr_base[i], RB_CHUNK_SIZE, TO_DEVICE);
		}
	}

	while (send_work_pool) {
		struct sw *work = send_work_pool;
		send_work_pool = work->next;
		kfree(work);
	}
	ring_buffer_destroy(&xdma_send_buff);

	while (xdma_work_pool) {
		struct xdma_work *xw = xdma_work_pool;
		xdma_work_pool = xw->next;
		kfree(xw);
	}

	MSGPRINTK("Popcorn message layer over RDMA unloaded\n");
	return;
}

static int __init init_kmsg_xdma(void)
{
  int i, ret;

  MSGPRINTK("\n ... Loading Popcorn messaging Layer over XDMA ...\n");

  pcn_kmsg_set_transport(&transport_xdma);

  pci_dev = pci_get_device(VEND_ID, DEV_ID, NULL);
  if(pci_dev == NULL) goto out;

  ret =__config_pcie(pci_dev);
  if(ret){
    goto invalid;
  }
  
  ctl_address = __pci_map(pci_dev, CTL)
  if(!ctl_address)
  { 
    MSGPRINTK("XDMA Configuration Failed\n");
    goto invalid;
  }

   bypass_address = __pci_map(pci_dev, BYPASS);
   if(!bypass_address)
   {
   	 MSGPRINTK("XDMA Configuration Failed\n");
     goto invalid;
   }

   xdma_ctl = __remap_regions(ctl_address, XDMA_SIZE);
   if(!xdma_ctl) goto invalid;

   xdma_bypass = __remap_regions(bypass_address, BYPASS_SIZE);
   if(!xdma_bypass) goto invalid;

  MSGPRINTK("\n XDMA Layer Configured ...\n");

  i = __get_node_info();
  printk("Node number: %d\n", i);
  
  set_popcorn_node_online(i, true);

  if(__setup_xdma_handler())
    {
      goto out_free;
    }
  if(__setup_ring_buffer())
  {
  	goto out_free;
  }

  if(__setup_recv_buffer())
  {
  	goto out_free;
  }

  broadcast_my_node_info(i);

  PCNPRINTK("Ready on XDMA\n");

  return 0;

out:
	exit_kmsg_xdma();
    MSGPRINTK("PCIe Device not found!!\n");
    return -EINVAL;

invalid: 
	exit_kmsg_xdma();
    MSGPRINTK("DMA Bypass not found!..\n");
    return -EINVAL;

out_free:
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
