/* Ethernet DMA Transfer Application */

#include <stdio.h>
#include "xil_types.h"
#include "xil_io.h"
#include "xtmrctr.h"
#include "xparameters.h"
#include "xxxvethernet.h"

/* GPIOs for monitoring status */

#define gpioRd1 XPAR_GPIO_0_BASEADDR
#define gpioRd2 XPAR_GPIO_0_BASEADDR + 0x08

#define gpioRst1 XPAR_GPIO_2_BASEADDR
#define gpioRst2 XPAR_GPIO_2_BASEADDR + 0x08

#define rxstat XPAR_GPIO_1_BASEADDR

unsigned int *bram = XPAR_BRAM_0_BASEADDR;
int i, ret, recv, send;
unsigned int start_time = 0, end_time1=0, end_time2=0, end_time3 =0 , time_h2c = 0, time_c2h = 0, time_recv = 0;
static int nid;

XTmrCtr timer;

#define desc_byp1 XPAR_BYPASS_CONTROLLER_V1_0_BASEADDR
#define desc_byp2 XPAR_BYPASS_CONTROLLER_V1_1_BASEADDR
#define desc_byp3 XPAR_BYPASS_CONTROLLER_V1_3_BASEADDR
#define desc_byp4 XPAR_BYPASS_CONTROLLER_V1_2_BASEADDR

/* H2C Descriptor - Channel 0 Bypass Configuration */

#define Ctl1 desc_byp1 + 0x00
#define Control1 desc_byp1 + 0x1C
#define DA1 desc_byp1 + 0x04
#define SA1 desc_byp1 + 0x0C
#define length1 desc_byp1 + 0x14
#define N1 desc_byp1 + 0x18

/* C2H Descriptor - Channel 0 Bypass Configuration */

#define Ctl2 desc_byp2 + 0x00
#define Control2 desc_byp2 + 0x1C
#define DA2 desc_byp2 + 0x04
#define SA2 desc_byp2 + 0x0C
#define length2 desc_byp2 + 0x14
#define N2 desc_byp2 + 0x18

/* H2C Descriptor - Channel 1 Bypass Configuration */

#define Ctl3 desc_byp3 + 0x00
#define Control3 desc_byp3 + 0x1C
#define DA3 desc_byp3 + 0x04
#define SA3 desc_byp3 + 0x0C
#define length3 desc_byp3 + 0x14
#define N3 desc_byp3 + 0x18

/* C2H Descriptor - Channel 1 Bypass Configuration */

#define Ctl4 desc_byp4 + 0x00
#define Control4 desc_byp4 + 0x1C
#define DA4 desc_byp4 + 0x04
#define SA4 desc_byp4 + 0x0C
#define length4 desc_byp4 + 0x14
#define N4 desc_byp4 + 0x18


/* XDMA Register Configuration */

// Channel 0

#define xdma XPAR_XDMA_0_BASEADDR
#define h2cControl xdma + 0x04
#define h2cChannel xdma + 0x40
#define c2hControl xdma + 0x1004
#define c2hChannel xdma + 0x1040
#define h2cintr xdma + 0x90
#define c2hintr xdma + 0x1090
#define c2hdesc xdma + 0x1048
#define h2cdesc xdma + 0x048

// Channel 1


#define h2c1Control xdma + 0x104
#define h2c1Channel xdma + 0x140
#define c2h1Control xdma + 0x1104
#define c2h1Channel xdma + 0x1140
#define h2c1intr xdma + 0x190
#define c2h1intr xdma + 0x1190
#define c2h1desc xdma + 0x1148
#define h2c1desc xdma + 0x148

// Common

#define chirq xdma + 0x2010
#define irq xdma + 0x2044
#define irqmask xdma + 0x2018
#define irqen xdma + 0x2014
#define SGDMA xdma + 0x6010

/* 25G Ethernet Registers */

#define xxv XPAR_XXV_ETHERNET_1_BASEADDR
#define xxv_rxen xxv + 0x014
#define xxv_txen xxv + 0x00C
#define xxv_txtotal xxv + 0x710
#define xxv_txgood xxv + 0x0718
#define xxv_rxtotal xxv + 0x818
#define xxv_rxgood xxv + 0x820

#define xxv1 XPAR_XXV_ETHERNET_0_BASEADDR
#define xxv1_rxen xxv1 + 0x014
#define xxv1_txen xxv1 + 0x00C


#define stat_tx xxv + 0x0400
#define stat_rx xxv + 0x0404

#define thresh 0x100
#define KMSG_MAX_SIZE 0x1000

enum {
	H2C = 0,
	C2H = 1,
};


enum {
	TO_HOST = 0,
	FROM_HOST = 1,
};
enum {
	CH0 = 0,
	CH1 = 1,
};

int init_xxv(void)
{
	/* Ethernet Core Bringup */

	int ret;
	Xil_Out32(xxv_rxen, 0x00000001);
	Xil_Out32(xxv1_rxen, 0x00000001);
	Xil_Out32(xxv_txen, 0x010);
	Xil_Out32(xxv1_txen, 0x010);
	xil_printf("Initializing Ethernet ....\n\r");
	Xil_Out32(xxv_txen, 0x00000000);
	Xil_Out32(xxv1_txen, 0x00000000);
	Xil_Out32(xxv_txen, 0x00000001);
	Xil_Out32(xxv1_txen, 0x00000001);
	ret = Xil_In32(rxstat);

	return ret;
}

void init_timer(void)
{
	XTmrCtr_Initialize(&timer, 0);
    XTmrCtr_Reset(&timer, 0);
}

u32 init_xdma(void)
{
       Xil_Out32(h2cControl, 0x00);
       Xil_Out32(c2hControl, 0x00);
       Xil_Out32(h2c1Control, 0x00);
       Xil_Out32(c2h1Control, 0x00);

       Xil_Out32(h2cChannel, 0x04);
       Xil_Out32(c2hChannel, 0x04);
       Xil_Out32(h2c1Channel, 0x04);
       Xil_Out32(c2h1Channel, 0x04);

	 /* H2C Configuration */

	    Xil_Out32(SA1, 0x00);
	    Xil_Out32(DA1, 0x00);
	    Xil_Out32(DA1 + 0x04, 0x0000);

	    Xil_Out32(Ctl1, 0x3);
	    Xil_Out32(N1, 1);

	    Xil_Out32(SA3, 0x00);
	    Xil_Out32(DA3, 0x00);
	    Xil_Out32(DA3 + 0x04, 0x0000);

	    Xil_Out32(Ctl3, 0x3);
	    Xil_Out32(N3, 1);

	    /* C2H Configuration */

	    Xil_Out32(SA2, 0x00);
	    Xil_Out32(DA2, 0x00);
	    Xil_Out32(SA2 + 0x04, 0x00);
	    Xil_Out32(Ctl2, 0x3);
	    Xil_Out32(N2, 1);

	    Xil_Out32(SA4, 0x00);
	   	Xil_Out32(DA4, 0x00);
	   	Xil_Out32(SA4 + 0x04, 0x00);
	   	Xil_Out32(Ctl4, 0x3);
	   	Xil_Out32(N4, 1);

	    Xil_Out32(h2cintr, 0x04);
	    Xil_Out32(c2hintr, 0x04);
	    Xil_Out32(h2c1intr, 0x04);
	    Xil_Out32(c2h1intr, 0x04);
	    Xil_Out32(chirq, 0x0F);

	    return (Xil_In32(h2cChannel) || Xil_In32(h2cControl) || Xil_In32(c2hChannel) || Xil_In32(c2hControl) ||
	    		Xil_In32(h2c1Channel) || Xil_In32(h2c1Control) || Xil_In32(c2h1Channel) || Xil_In32(c2h1Control));
}

int configure_nid(int nid)
{
	bram[0] = nid;

	return bram[0];
}

void clear_interrupts(int x, int y)
{
	if(x)
	{
		if(!y)
		{
			Xil_Out32(irqmask, 0x01);
			Xil_In32(xdma  + 0x44);
			Xil_Out32(irqen, 0x01);
			//xil_printf("Status after clearing: %lx\n", Xil_In32(irq));
		}
		else
		{
			Xil_Out32(irqmask, 0x02);
			Xil_In32(xdma  + 0x144);
			Xil_Out32(irqen, 0x02);
			//xil_printf("Status after clearing: %lx\n", Xil_In32(irq));
		}
	}
	else
	{
		if(!y)
		{
			Xil_Out32(irqmask, 0x04);
			Xil_In32(xdma  + 0x1044);
			Xil_Out32(irqen, 0x04);
			//xil_printf("Status after clearing: %lx\n", Xil_In32(irq));
		}
		else
		{
			Xil_Out32(irqmask, 0x08);
			Xil_In32(xdma  + 0x1144);
			Xil_Out32(irqen, 0x08);
			//xil_printf("Status after clearing: %lx\n", Xil_In32(irq));
		}
	}
}
int config_descriptors(u32 addr_msb, u32 addr_lsb, size_t size, int z, int y)
{
	if(z)
	{
		if(!y)
		{
			Xil_Out32(SA1, addr_msb);
					Xil_Out32(SA1 + 0x04, addr_lsb);
					Xil_Out32(length1, size);

			        xil_printf("Address and size to be sent in Ch0: %lx and %lx\n\r",Xil_In32(SA1 + 0x04), size);
					if(Xil_In32(SA1+0x04) != addr_lsb) return 0;
		}
		else
		{
			Xil_Out32(SA3, addr_msb);
					Xil_Out32(SA3 + 0x04, addr_lsb);
					Xil_Out32(length3, size);

			        xil_printf("Address and size to be sent in CH1: %lx and %lx\n\r",Xil_In32(SA3 + 0x04), size);
					if(Xil_In32(SA3+0x04) != addr_lsb) return 0;
		}

		return 1;
	}
	else
	{
		if(!y)
		{
			Xil_Out32(DA2, addr_msb);
			Xil_Out32(DA2 + 0x04, addr_lsb);
			Xil_Out32(length2, size);
			xil_printf("Address and size to be received in ch0: %lx and %lx\n\r",Xil_In32(DA2 + 0x04), size);
			if(Xil_In32(DA2+0x04) != addr_lsb) return 0;
		}
		else
		{
			Xil_Out32(DA4, addr_msb);
			Xil_Out32(DA4 + 0x04, addr_lsb);
			Xil_Out32(length4, size);
			xil_printf("Address and size to be received in ch1: %lx and %lx\n\r",Xil_In32(DA4 + 0x04), size);
			if(Xil_In32(DA4+0x04) != addr_lsb) return 0;
		}


		return 1;
	}
}

void reset_desc(int x, int y)
{
	if(x){
		if(!y)
		{
			Xil_Out32(Control2, 0x80000000);
		}
		else
		{
			Xil_Out32(Control4, 0x80000000);
		}

	}
    else{
    	if(!y)
    	{
    		Xil_Out32(Control1, 0x80000000);
    	}
    	else
    	{
    		Xil_Out32(Control3, 0x80000000);
    	}

    }
}

void reset_xdma(int x)
{
	if(!x)
	{
		Xil_Out32(c2hControl, 0x00);
		Xil_Out32(h2cControl, 0x00);
		//Xil_Out32(c2hChannel, 0x04);
		//Xil_Out32(h2cChannel, 0x04);
	}
	else
	{
		Xil_Out32(h2c1Control, 0x00);
		Xil_Out32(c2h1Control, 0x00);
		//Xil_Out32(c2h1Channel, 0x04);
		//Xil_Out32(h2c1Channel, 0x04);
	}
}

void reset_fifo(int y)
{
	if(!y)
	{
		Xil_Out32(gpioRst1, 0x00);
		Xil_Out32(gpioRst1, 0x01);
	}
	else
	{
		Xil_Out32(gpioRst2, 0x00);
		Xil_Out32(gpioRst2, 0x01);
	}
}

int clear_bram(int x, int y)
{
	if(x)
	{
		if(!y)
		{
			for(int i=1; i < 10; i++)
			{
				bram[i] = 0x00;
			}
			return 1;
		}
		else
		{
			for(int i=30; i < 40; i++)
				{
					bram[i] = 0x00;
				}
			return 1;
		}
	}
	else
	{
		if(!y)
		{
			for(int i=10; i < 20; i++)
				{
					bram[i] = 0x00;
				}
			return 1;
		}
		else
		{
			for(int i=20; i < 30; i++)
				{
					bram[i] = 0x00;
				}
			return 1;
		}

	}
	return 0;
}

int xdma_transfer(int y, int z)
{
	/* H2C Send - From Host to FPGA */
	if(y)
	{
		if(!z)
		{
			XTmrCtr_Reset(&timer, 0);
			start_time = XTmrCtr_GetValue(&timer,0);
			XTmrCtr_Start(&timer, 0);
			Xil_Out32(h2cControl, 0x05);
			Xil_Out32(Control1 , 0x01);
			while((Xil_In32(irq) & 0x01) != 1);
			Xil_Out32(Control1 , 0x00);
			reset_desc(FROM_HOST, z);
			reset_xdma(z);
			//xil_printf("Status of DMA: %x and %x\n\r", Xil_In32(h2cChannel), Xil_In32(h2cControl));
			//xil_printf("Status of XXV: %x and %x\n", Xil_In32(xxv_txtotal), Xil_In32(xxv_txgood));
			XTmrCtr_Stop(&timer, 0);
			end_time1 = XTmrCtr_GetValue(&timer,0);

			return 0;
			//xil_printf("Time taken for DMA transfer from Host to Device: %d\n\r",(end_time1 - start_time));
			//xil_printf("Status: %lx\n", Xil_In32(irq));

		}
		else
		{
			XTmrCtr_Reset(&timer, 0);
			start_time = XTmrCtr_GetValue(&timer,0);
			XTmrCtr_Start(&timer, 0);
			Xil_Out32(h2c1Control, 0x05);
			Xil_Out32(Control3 , 0x01);
			while((Xil_In32(irq) & 0x02) != 2);
			Xil_Out32(Control3 , 0x00);
			reset_desc(FROM_HOST, z);
			reset_xdma(z);
			XTmrCtr_Stop(&timer, 0);
			end_time1 = XTmrCtr_GetValue(&timer,0);

			return 0;
			//xil_printf("Time taken for DMA transfer from Host to Device: %d\n\r",(end_time1 - start_time));
			//xil_printf("Status: %lx\n", Xil_In32(irq));

			//xil_printf("Status: %lx\n", Xil_In32(h2c1Channel));

		}
	}

	/* C2H Send - From FPGA to Host */

	else
	{
		if(!z)
		{
			XTmrCtr_Reset(&timer, 0);
			start_time = XTmrCtr_GetValue(&timer,0);
			XTmrCtr_Start(&timer, 0);
			Xil_Out32(c2hControl, 0x05);
			Xil_Out32(Control2, 0x01);
			while((Xil_In32(irq) & 0x04) != 0x04);
			Xil_Out32(Control2 , 0x00);
			reset_desc(TO_HOST, z);
			reset_xdma(z);
			//xil_printf("Status of DMA: %x and %x\n\r", Xil_In32(c2hChannel), Xil_In32(c2hControl));
			//xil_printf("Status of XXV: %x and %x\n",Xil_In32(xxv_rxtotal), Xil_In32(xxv_rxgood));
			XTmrCtr_Stop(&timer, 0);
			end_time1 = XTmrCtr_GetValue(&timer,0);

			return 0;
			//xil_printf("Time Taken for DMA transfer from Device to Host: %d\n\r", (end_time1 - start_time));
			//xil_printf("Status: %lx\n", Xil_In32(irq));

		}
		else
		{
			XTmrCtr_Reset(&timer, 0);
			start_time = XTmrCtr_GetValue(&timer,0);
			XTmrCtr_Start(&timer, 0);
			Xil_Out32(c2h1Control, 0x05);
			Xil_Out32(Control4, 0x01);
			while((Xil_In32(irq) & 0x08) != 0x08);
			Xil_Out32(Control4 , 0x00);
			reset_desc(TO_HOST, z);
			reset_xdma(z);
			XTmrCtr_Stop(&timer, 0);
			end_time1 = XTmrCtr_GetValue(&timer,0);

			return 0;
			//xil_printf("Time Taken for DMA transfer from Device to Host: %d\n\r", (end_time1 - start_time));
			//xil_printf("Status: %lx\n", Xil_In32(irq));

		}
	}
	return 1;
}


void __xdma_c2h(u32 addr_msb, u32 addr_lsb, size_t size, int z)
{
	//xil_printf("Receiving ... \n\r");
	ret = config_descriptors(addr_msb, addr_lsb, size, TO_HOST, z);


	recv = xdma_transfer(TO_HOST, z);

    //xil_printf("Interrupt Status: %x and complete desc: %x\n\r", Xil_In32(irq), Xil_In32(c2hdesc));

	//clear_interrupts(TO_HOST, z);
	//reset_desc(TO_HOST, z);
	reset_fifo(z);
}

void __xdma_h2c(u32 addr_msb, u32 addr_lsb, size_t size, int z)
{
	//xil_printf("Sending ...\n\r");
    ret = config_descriptors(addr_msb, addr_lsb, size, FROM_HOST, z);
	send = xdma_transfer(FROM_HOST, z);

	//reset_xdma(z);
	clear_bram(FROM_HOST, z);
	//clear_interrupts(FROM_HOST, z);
	//reset_desc(FROM_HOST, z);
}

/* Main Function */

void __register_handler(void)
{
	int execute;
	execute = 1;


    unsigned long addr_lsb, addr_msb;
    size_t size;

	while(execute){
	   xil_printf("Execute\n\r");
	   while(!(bram[2] || (Xil_In32(gpioRd1) > 0x10) || bram[31] || (Xil_In32(gpioRd2) > 0x10)));
	   if(Xil_In32(gpioRd1) > 0x10)
	   {
		           //xil_printf("Contents : %x and %x and %x and %x\n\r", bram[10], bram[11], bram[12], Xil_In32(gpioRd1));
		   	   	   addr_msb = bram[10];
		   	   	   addr_lsb = bram[11];
		   	   	   size = bram[12];

	       	    //Receiving process
		   	   __xdma_c2h(addr_msb, addr_lsb, size, CH0);

	   }
	   else if(Xil_In32(gpioRd2) > 0x10)
	   {
		   //xil_printf("Contents inside C2h of CH1: %x and %x and %x and %x\n\r", bram[20], bram[21], bram[22], Xil_In32(gpioRd2));
		   		   	   	   addr_msb = bram[20];
		   		   	   	   addr_lsb = bram[21];
		   		   	   	   size = bram[22];

		   	       	    //Receiving process
		   		   	   __xdma_c2h(addr_msb, addr_lsb, size, CH1);
	   }
	   else if(bram[2])
	   {

	           //Sending Process

	        	   addr_msb = bram[1];
	        	   addr_lsb = bram[2];
	        	   size = KMSG_MAX_SIZE;



	        	   //xil_printf("Contents : %x and %x and %x\n\r", bram[1], bram[2], bram[3]);
	        	   __xdma_h2c(addr_msb, addr_lsb, size, CH0);
	    }
	    else if(bram[31])
	    {
	        	   //Sending Process
	        	   //xil_printf("Inside Channel 1 H2C\n");
	        	   addr_msb = bram[30];
	        	   addr_lsb = bram[31];
	        	   size = bram[32];
	        	  	__xdma_h2c(addr_msb, addr_lsb, size, CH1);
	     }
	    else
	    {
	    	xil_printf("Fault in this function!!!\n\r");
	    }
	}
}

int main()
{
    init_platform();

    init_timer();
    nid = 0;
    i = init_xdma();
    if(i) {
    	goto out_xdma;
    }

    i = init_xxv();
    xil_printf("Stats of xxv: %x and %x \n\r", Xil_In32(stat_tx), Xil_In32(stat_rx));
    if(!i)
    {
    	goto out;
    }
    i = configure_nid(nid);
    xil_printf("... Ethernet Link Success ...\n\r");
    xil_printf("Handler Registered for node: %d\n\r", i);
    reset_fifo(CH0);
    reset_fifo(CH1);

    clear_bram(H2C, CH0);
    clear_bram(H2C, CH1);
    clear_bram(C2H, CH0);
    clear_bram(C2H, CH1);
    __register_handler();

    cleanup_platform();
    return 0;


  out:
  	  cleanup_platform();
  	  xil_printf("Ethernet Link Failed!");
  	  return 1;
  out_xdma:
  	  xil_printf("XDMA Init Failed! Stats : %x and %x and %x and %x\n\r", Xil_In32(h2cChannel), Xil_In32(h2cControl), Xil_In32(c2hChannel), Xil_In32(c2hControl));
  	  xil_printf("Stats contd : %x and %x and %x and %x\n\r", Xil_In32(h2c1Channel), Xil_In32(h2c1Control), Xil_In32(c2h1Channel), Xil_In32(c2h1Control));
  	  return 1;
}
