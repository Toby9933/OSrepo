#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "wmap.h"
uint sys_wmap(void){
    uint addr;
    int length, flags, fd;

    // Retrieve arguments
    if (argint(0, (int*)&addr) < 0 ||
        argint(1, &length) < 0 ||
        argint(2, &flags) < 0 ||
        argint(3, &fd) < 0)
        return FAILED;

    // Validate flags and parameters
    if (length <= 0 || !(flags & MAP_SHARED) || !(flags & MAP_FIXED))
        return FAILED;

    if (addr % PGSIZE != 0 || addr < 0x60000000 || addr >= 0x80000000)
        return FAILED;

    struct proc *p = myproc();

    // Check if there's space for a new mapping
    if (p->mmap_count >= MAX_WMMAP_INFO)
        return FAILED;

    // Record the mapping
    struct mmap_region *mmap = &p->mmap_regions[p->mmap_count++];
    mmap->addr = addr;
    mmap->length = length;
    mmap->flags = flags;
    mmap->fd = (flags & MAP_ANONYMOUS) ? -1 : fd;

    // Lazy allocation: No physical pages are allocated yet
    return addr;
}

int sys_wunmap(void){
     uint addr;

//     Retrieve the argument
  if (argint(0, (int*)&addr) < 0)
  return FAILED;
// Ensure the address is page-aligned
   if (addr != PGROUNDDOWN(addr)) {
       return FAILED; // Address is not valid
 	}
    struct proc *p = myproc();

//      Find the mapping that starts at addr
   struct mmap_region *mmap = 0;
   for (int i = 0; i < p->mmap_count; i++) {
      if (p->mmap_regions[i].addr == addr) {
	  mmap = &p->mmap_regions[i];
           break;
	    }
	}

//     If no mapping is found, return failure
    if (mmap ==0) {
       return FAILED;
	}
//   If the mapping is file-backed and shared, write data back to the file
     if (!(mmap->flags & MAP_ANONYMOUS) && (mmap->flags & MAP_SHARED)) {
     struct file *f = p->ofile[mmap->fd];
              if (f == 0) {
 	  return FAILED; // File descriptor invalid
	    }

//         Write memory back to the file
	 for (uint va = addr; va < addr + mmap->length; va += PGSIZE) {
	  void *data = P2V(PTE_ADDR(*walkpgdir(p->pgdir, (void*)va, 0)));
            filewrite(f, data, PGSIZE); //use writei
	    }
	}

//     Unmap all pages in the region
    for (uint va = addr; va < addr + mmap->length; va += PGSIZE) {
    pte_t *pte = walkpgdir(p->pgdir, (void*)va, 0);
	if (pte && (*pte & PTE_P)) { // If page is present
	  uint pa = PTE_ADDR(*pte);   // Extract physical address
    kfree((void *)pa);            // Free physical memory  multiple the length of the page 
    *pte = 0;                  // Clear the PTE
	    }
	}

//     Remove the mapping from mmap_regions
   p->mmap_count--;
    *mmap = p->mmap_regions[p->mmap_count]; //this is the array that holds the refrence count to every physical page. When accessing a physical page, you should acces it by the PFN, which is phyisical address / PGSIZE

   return SUCCESS; // Unmap successful
    }
int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}
