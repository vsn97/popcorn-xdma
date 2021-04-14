#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include <popcorn/stat.h>
#include <popcorn/debug.h>
#include <popcorn/pcn_kmsg.h>
#include "pcie.h"

void __iomem *xdma_axi;
void __iomem *xdma_ctl;

void write_register(u32 value, void *iomem)
{
	iowrite32(value, iomem);
}

inline u32 read_register(void *iomem)
{
	return ioread32(iomem);
}


static void __init_descriptor_bypass(void)
{
	write_register(0x13, xdma_axi + Ctl1);
	write_register(1, xdma_axi + N1);
	write_register(0x13, xdma_axi + Ctl2);
	write_register(1, xdma_axi + N2);
	write_register(0x13, xdma_axi + Ctl3);
	write_register(1, xdma_axi + N3);
	write_register(0x13, xdma_axi + Ctl4);
	write_register(1, xdma_axi + N4);
}

static int __init_xdma(void)
{
	/* Resetting the XDMA */

	write_register(0, xdma_ctl + h2c_ctl);
	write_register(0, xdma_ctl + h2c1_ctl);
	write_register(0, xdma_ctl + c2h_ctl);
	write_register(0, xdma_ctl + c2h1_ctl);

	/* Configuring the Interrupt Enable Masks */

	write_register(0x30003, xdma_ctl + sgdma);
	write_register(0x04, xdma_ctl + h2cintr);
	write_register(0x04, xdma_ctl + h2c1intr);
	write_register(0x04, xdma_ctl + c2hintr);
	write_register(0x04, xdma_ctl + c2h1intr);

	write_register(0x0F, xdma_ctl + ch_irqen);
	write_register(0x03, xdma_ctl + usr_irqen);

	return (read_register(xdma_ctl + h2c_ctl) || read_register(xdma_ctl + h2c1_ctl) || 
		read_register(xdma_ctl + c2h_ctl) || read_register(xdma_ctl + c2h1_ctl));

}

static void __init_xxv(void)
{
	/* Enabling the RX and TX in the Ethernet Subsystem */

	write_register(0x01, xdma_axi + xxv_rxen);
	write_register(0x01, xdma_axi + xxv1_rxen);
	write_register(0x10, xdma_axi + xxv_txen);
	write_register(0x10, xdma_axi + xxv1_txen);

	msleep(100);
	write_register(0, xdma_axi + xxv_txen);
	write_register(0, xdma_axi + xxv1_txen);
	write_register(0x01, xdma_axi + xxv_txen);
	write_register(0x01, xdma_axi + xxv1_txen);

}


void __channel_interrupts_disable(int z, int x)
{
	int i;
	//PCNPRINTK("Inside channel interrupts disable\n");
	if(z) {
		if(!x) {

			write_register(0x00,  (u32 *)(xdma_ctl + h2c_ctl));
			write_register(0x01, (u32 *)(xdma_ctl + ch_irq_mask));
			read_register((u32 *)(xdma_ctl + h2c_stat));
			//i = read_register((u32 *)(xdma_ctl + irq_enable));
			write_register(ioread32((u32 *)(xdma_ctl + ch_irq_enable)) | 0x01, (u32 *)(xdma_ctl + ch_irq_enable));
			//while(read_register(xdma_ctl + ch_irq));
		} else {

			write_register(0x00, (u32 *)(xdma_ctl + h2c1_ctl));
			write_register(0x02, (u32 *)(xdma_ctl + ch_irq_mask));
			read_register((u32 *)(xdma_ctl + h2c1_stat));
			//i = ioread32((u32 *)(xdma_ctl + irq_enable));
			write_register(ioread32((u32 *)(xdma_ctl + ch_irq_enable)) | 0x02, (u32 *)(xdma_ctl + ch_irq_enable));
			//while(read_register(xdma_ctl + ch_irq));
		}
	} else {
		if(!x) {
			//("Pending Interrupts: %d\n", read_register(xdma_ctl + ch_irq_pending));
		    write_register(0x00, (u32 *)(xdma_ctl + c2h_ctl));
		    write_register(0x04, (u32 *)(xdma_ctl + ch_irq_mask));
			read_register((u32 *)(xdma_ctl + c2h_stat));
			//i = read_register((u32 *)(xdma_ctl + irq_enable));
			write_register(ioread32((u32 *)(xdma_ctl + ch_irq_enable)) | 0x04, (u32 *)(xdma_ctl + ch_irq_enable));
			//PCNPRINTK("Pending Interrupts: %d\n", read_register(xdma_ctl + ch_irq_pending));
			//while(read_register(xdma_ctl + ch_irq));
		} else {

			write_register(0x00, (u32 *)(xdma_ctl + c2h1_ctl));
			write_register(0x08, (u32 *)(xdma_ctl + ch_irq_mask));
			read_register((u32 *)(xdma_ctl + c2h1_stat));
			//i = read_register((u32 *)(xdma_ctl + irq_enable));
			write_register(ioread32((u32 *)(xdma_ctl + ch_irq_enable)) | 0x08, (u32 *)(xdma_ctl + ch_irq_enable));
			//while(read_register(xdma_ctl + ch_irq));
		}
	}

	//PCNPRINTK("Exiting channel interrupts disable\n");
}

void __user_interrupts_disable(int x)
{
	if(!x) {
		write_register(0x01, (u32 *)(xdma_ctl + usr_irq_mask));
		write_register(ioread32((u32 *)(xdma_ctl + usr_irq_enable)) | 0x01, (u32 *)(xdma_ctl + usr_irq_enable));

	} else {
		write_register(0x02, (u32 *)(xdma_ctl + usr_irq_mask));
		write_register(ioread32((u32 *)(xdma_ctl + usr_irq_enable)) | 0x02, (u32 *)(xdma_ctl + usr_irq_enable));
	}

}

int config_descriptors_bypass(dma_addr_t dma_addr, size_t size, int y, int z)
{
	u32 addr_msb, addr_lsb;

	addr_msb = (u32)((dma_addr & XDMA_MSB_MASK) >> 32);
	addr_lsb = (u32)(dma_addr & XDMA_LSB_MASK);
	//PCNPRINTK("Inside the config_descriptors_bypass\n");
	if(y){
		if(!z) {

			write_register(addr_msb, xdma_axi + SA1);
			write_register(addr_lsb, xdma_axi + SA1 + 0x04);
			if(size < thresh) {
				size = thresh;
			}
			write_register(size, xdma_axi + length1);
			return 0;

		} else {

			write_register(addr_msb, xdma_axi + SA3);
			write_register(addr_lsb, xdma_axi + SA3 + 0x04);
			write_register(0x1000, xdma_axi + length3);
			return 0;

		}
	} else {
		if(!z) {

			write_register(addr_msb, xdma_axi + DA2);
			write_register(addr_lsb, xdma_axi + DA2 + 0x04);
			write_register(size, xdma_axi + length2);
			return 0;

		} else {

			write_register(addr_msb, xdma_axi + DA4);
			write_register(addr_lsb, xdma_axi + DA4 + 0x04);
			write_register(0x1020, xdma_axi + length4);
			return 0;

		}
	}
}

int xdma_transfer(int y, int z)
{
	//printk("Inside xdma_transfer\n");
	if(y){
		if(!z) {

			//PCNPRINTK("Inside xdma_transfer: %d\n", read_register(xdma_ctl + h2c_ch));
			write_register(0xFFFE25, xdma_ctl + h2c_ctl);
			write_register(0x01, xdma_axi + Control1);
			return 0;

		} else {

			//PCNPRINTK("Inside xdma_transfer: %d\n", read_register(xdma_ctl + h2c1_ch));
			write_register(0xFFFE25, xdma_ctl + h2c1_ctl);
			write_register(0x01, xdma_axi + Control3);
			return 0;

		}
	} else {
		if(!z) {

			//PCNPRINTK("Inside xdma_transfer: %d\n", read_register(xdma_ctl + c2h_ch));
			//while(read_register(xdma_ctl + c2h_ch));
			write_register(0xFFFE25, xdma_ctl + c2h_ctl);
			write_register(0x01, xdma_axi + Control2);
			//while(!(read_register(xdma_ctl + ch_irq) & 0x04));
			//while((read_register(xdma_ctl + ch_irq) & 0x04));
			return 0;

		} else {

			//PCNPRINTK("Inside xdma_transfer: %d\n", read_register(xdma_ctl + c2h1_ch));
			write_register(0xFFFE25, xdma_ctl + c2h1_ctl);
			write_register(0x01, xdma_axi + Control4);
			return 0;

		}
	}
}

int __init_pcie_xdma(struct pci_dev *pci_dev, void __iomem *p, void __iomem *g)
{
	int ret;

	xdma_ctl = p;
	xdma_axi = g;

	if(__init_xdma()) {
		return 1;
	}

	__init_xxv();

	__init_descriptor_bypass();

	return 0;
}