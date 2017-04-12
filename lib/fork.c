// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	if(!(err & FEC_WR))
		panic("Faulting access was not a write!!");

	pte_t pt_entry = uvpt[VPN(addr)];
	if(!(pt_entry & PTE_COW))
		panic("Faulting access was not on acopy-on-write page!!");
//cprintf("inside page fault 1\n");
	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.

	// LAB 4: Your code here.
	if(sys_page_alloc(0,(void*)PFTEMP,PTE_P|PTE_U|PTE_W)<0)
		panic("page_alloc not working!!");
	void *addr_round = ROUNDDOWN(addr,PGSIZE);

	//move the new page to the old page's address
	memmove((void*)PFTEMP, addr_round, PGSIZE);
//cprintf("inside page fault 2\n");
	if(sys_page_map(0, (void*)PFTEMP, 0, addr_round, PTE_P|PTE_U|PTE_W)<0)
		panic("page map not working!!");

	if(sys_page_unmap(0,(void*)PFTEMP)<0)
		panic("page unmap not working!!");
	//panic("pgfault not implemented");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	//panic("duppage not implemented");
	pte_t pt_entry = uvpt[pn];
//cprintf("under duppage!!\n");
	int perm = pt_entry & PTE_SYSCALL;
	//int child_perm = perm;
	void *page_addr = (void*)((uintptr_t)pn*PGSIZE);


	//LAB 5: modifications for PTE_SHARE
	if(perm & PTE_SHARE){
		if((r = sys_page_map(0, page_addr, envid, page_addr, perm)) < 0)
			panic("Wrong with share permissions\n");
	}else if((perm & PTE_W) || (perm & PTE_COW)){
		perm |= PTE_COW;  // cow permission
		perm &= ~PTE_W;   // not write
//cprintf("duppage page_map 1\n");
		if(sys_page_map(0,page_addr,envid,page_addr,perm)<0)
			panic("Wrong with setting permission for child\n");
//cprintf("duppage page_map 2\n");
		if(sys_page_map(0,page_addr,0,page_addr,perm)<0)
			panic("wrong with setting permission for parent\n");
	}else{
//cprintf("duppage page_map 3\n");
	// fetch address
	//void* page_addr = (void*)((uintptr_t)pn*PGSIZE);
		if(sys_page_map(0,page_addr,envid,page_addr,perm)<0)
			panic("Something wrong with duppage!!");
	}
	
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	set_pgfault_handler(pgfault);   // set up page fault handler appropriately

	envid_t child = sys_exofork();   // create a child
	if(child < 0)
		panic("Fork is not working!!\n");
//cprintf("Before child 0");
	if(child==0){
//cprintf("I am in the child\n");
		thisenv = &envs[ENVX(sys_getenvid())];
//cprintf("I am in child after this env\n");
		return 0;
	}
	
	//allocate page for child exception stack
	if(sys_page_alloc(child,(void*)UXSTACKTOP-PGSIZE,PTE_P|PTE_U|PTE_W)<0)
		panic("Could not allocate page for child exception stack!!\n");

	//walk through the page table to know which page mappings to be duplicated
	size_t i,j,k,l;
	int pdpe_ctr=0, pdp_ctr=0, pt_ctr=0;
	for(i=0 ; i<VPML4E(UTOP) ; i++){
		if(uvpml4e[i] & PTE_P){
			for(j=0 ; j<NPDPENTRIES ; j++, pdpe_ctr++){
				if(uvpde[pdpe_ctr] & PTE_P){
					for(k=0 ; k<NPDENTRIES ; k++, pdp_ctr++){
						if(uvpd[pdp_ctr ] & PTE_P){
							for(l=0 ; l<NPTENTRIES ; l++, pt_ctr++){
								if(uvpt[pt_ctr] & PTE_P){
//cprintf("if under1\n");
									if((pt_ctr)!=VPN(UXSTACKTOP-PGSIZE)){
//cprintf("if under2\n");
										if(duppage(child, (unsigned)(pt_ctr ))<0)
											panic("Page mapping cannot be copied for child!!!");
									}
								}
							}
						}else{
							pt_ctr = (pdp_ctr+1)*NPTENTRIES;
						}
					}
				}else{
					pdp_ctr = (pdpe_ctr+1)*NPDENTRIES;
				}
			}
		}else{
			pdpe_ctr = (i+1)*NPDPENTRIES;
		}
	}
//cprintf("after walking\n");	
	// we need page_fault upcall too as this is user env
	extern void _pgfault_upcall(void);
	if(sys_env_set_pgfault_upcall(child,_pgfault_upcall)<0)
		panic("Pgfault upcall for child could not be set!!");
	
	// mark child as runnable
//cprintf("marking child as runnable\n");
	if(sys_env_set_status(child,ENV_RUNNABLE)<0)
		panic("Status of child could not be set!!");
	return child;
	//panic("fork not implemented");
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
