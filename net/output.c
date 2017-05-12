#include "ns.h"
extern union Nsipc nsipcbuf;

    void
output(envid_t ns_envid)
{
    binaryname = "ns_output";

    // LAB 6: Your code here:
    // 	- read a packet from the network server
    //	- send the packet to the device driver
	int ret = 0;
cprintf("\n------------");
	while(1){
cprintf("\n^^^^^^^^^^^\n");
		ret = sys_ipc_recv(&nsipcbuf);
cprintf("\n++++++\n");
		if ((thisenv->env_ipc_from != ns_envid) ||(thisenv->env_ipc_value != NSREQ_OUTPUT)) {
cprintf("\n000000000000\n");
			continue;
		}
		while ((ret = sys_e1000_transmit(nsipcbuf.pkt.jp_data, nsipcbuf.pkt.jp_len)) < 0){
cprintf("\n111111111111111111\n");
			sys_yield();
		}
	}
}
