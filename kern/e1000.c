#include <kern/e1000.h>

// LAB 6: Your driver code here
volatile uint32_t *e1000_mem;

// Transmit descriptor array
struct trans_desc tx_desc[64] ;
struct trans_packet tx_pkt[64];

int
e1000_attach_func(struct pci_func *pcif){

	// Enable the device
	pci_func_enable(pcif);

	// virtual mempry mapping for the device
	e1000_mem = mmio_map_region(pcif->reg_base[0], pcif->reg_size[0]);

	// Test status
	cprintf("PCI status: %x\n", e1000_mem[2]);

	// Transmit initialization
	e1000_mem[E1000_TDBAL/4] = PADDR(tx_desc);
	e1000_mem[E1000_TDBAH/4] = 0x0;
	e1000_mem[E1000_TDLEN/4] = sizeof(struct trans_desc) * 64;
	e1000_mem[E1000_TDH/4] = 0x0;      //head of transmit queue
	e1000_mem[E1000_TDT/4] = 0x0;      //tail of transmit queue
	//e1000_mem[E1000_TCTL >> 2] = 0x4008A; //calculated as per the manual
	//e1000_mem[E1000_TIPG >> 2] = 0x60200A;
	
	e1000_mem[E1000_TCTL/4] = E1000_TCTL_EN | E1000_TCTL_PSP | (E1000_TCTL_CT & (0x10<<4)) | (E1000_TCTL_COLD & (0x40<<12));
	/*e1000_mem[E1000_TCTL/4] |= E1000_TCTL_PSP;
	e1000_mem[E1000_TCTL/4] &= ~E1000_TCTL_CT;
	e1000_mem[E1000_TCTL/4] |= (0x10) << 4;
	e1000_mem[E1000_TCTL/4] &= ~E1000_TCTL_COLD;
	e1000_mem[E1000_TCTL/4] |= (0x40) << 12;*/

	e1000_mem[E1000_TIPG/4] = 10 | (0x8<<10) | (0x6<<20);
	/*e1000_mem[E1000_TIPG/4] = 0x0;
	e1000_mem[E1000_TIPG/4] |= 0xA;
	e1000_mem[E1000_TIPG/4] |= (0x4) << 10;
	e1000_mem[E1000_TIPG/4] |= (0x6) << 20;*/ 

	// Descriptors with packets
	int i;
	for(i=0;i<64;i++){
		tx_desc[i].addr = PADDR(tx_pkt[i].buf);
		tx_desc[i].status |= E1000_TXD_STAT_DD;
		tx_desc[i].length =0;
	}

	return 0;
}

int
e1000_transmit(char *data, size_t n){
cprintf("\nHere\n");
	uint32_t tail = e1000_mem[E1000_TDT/4];
	if(tx_desc[tail].status & E1000_TXD_STAT_DD){
		memcpy(tx_pkt[tail].buf, data, n);
		tx_desc[tail].length = n;
		tx_desc[tail].status = 0;
		tx_desc[tail].cmd |=  E1000_TXD_CMD_RS | E1000_TXD_CMD_EOP;
		e1000_mem[E1000_TDT/4] = (tail+1) % 64;
		return 0;
cprintf("\n And now\n");
	}else{
cprintf("\n And then\n");
		return -1;
	}
}

