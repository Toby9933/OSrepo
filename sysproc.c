#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "wmap.h"
#include "fs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "file.h"

int sys_wmap(void){
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

    if (addr+length<0x60000000  || addr+length>= 0x80000000){
        return FAILED;
    }

    struct proc *p = myproc();

    // Check if there's space for a new mapping
    if (p->mmap_count+1 > MAX_WMMAP_INFO)
        return FAILED;

// Check for overlaps with existing mappings
    for (int i = 0; i < p->mmap_count; i++) {
        struct mmap_region *existing = &p->mmap_regions[i];//wamp.h
        uint existing_address_start = existing->addr;
        uint existing_address_end = existing_address_start + existing->length;
        if (existing_address_start <= addr && addr < existing_address_end)
          return FAILED;
    }
          
      
   
    // Record the mapping
    struct mmap_region *mmap = &p->mmap_regions[p->mmap_count];
    p->mmap_count++;

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
struct file *f ;
//   If the mapping is file-backed and shared, write data back to the file
    if (!(mmap->flags & MAP_ANONYMOUS) && (mmap->flags & MAP_SHARED)) {
      f =  p->ofile[mmap->fd];
              if (f == 0) {
 	            return FAILED; // File descriptor invalid
	            }

//         Write memory back to the file
    uint file_offset = 0; // Start writing from the beginning of the mapping
	 for (uint va = addr; va < addr + mmap->length; va += PGSIZE) {
	  // void *data = P2V(PTE_ADDR(*walkpgdir(p->pgdir, (void*)va, 0)));
    //         filewrite(f, data, PGSIZE); //use writei
      pte_t *pte = walkpgdir(p->pgdir, (void*)va, 0);
            if (pte && (*pte & PTE_P)) {
                int bytes_remaining = addr + mmap->length - va;
                if (bytes_remaining > PGSIZE)
                  bytes_remaining = PGSIZE;
                // void *data = P2V(PTE_ADDR(*pte)); // Get physical memory address
                begin_op();
                ilock(f->ip);
                writei(f->ip, (void*)va, file_offset, bytes_remaining);
                iunlock(f->ip);
                end_op();
                file_offset += PGSIZE;
            }
	    }
	}

//     Unmap all pages in the region
    for (uint va = addr; va < addr + mmap->length; va += PGSIZE) {
    pte_t *pte = walkpgdir(p->pgdir, (void*)va, 0);
	    if (pte && (*pte & PTE_P)) { // If page is present
	    uint pa = PTE_ADDR(*pte);   // Extract physical address
      kfree((void *)P2V(pa));            // Free physical memory  multiple the length of the page 
                      // Clear the PTE
	    }
      *pte = 0;  
	}

//     Remove the mapping from mmap_regions
   mmap->addr = 0;
   mmap->length = 0;
   mmap->fd = 0;
   mmap->flags = 0;
   mmap->n_loaded_pages = 0;
   mmap = 0;
   p->mmap_count--;
    // *mmap = p->mmap_regions[p->mmap_count]; //this is the array that holds the refrence count to every physical page. When accessing a physical page, you should acces it by the PFN, which is phyisical address / PGSIZE

   return SUCCESS; // Unmap successful
    }

extern pte_t *walkpgdir(pde_t *pgdir, const void *va, int alloc);

int getwmapinfo_helper(struct wmapinfo *wminfo)
{
  struct proc *p = myproc();
  pde_t *pgdir = p->pgdir;
  uint va;
  pte_t *pte;
  int total_mmaps = 0;

  // Initialize the wmapinfo structure to zero
  wminfo->total_mmaps = 0;
  memset(wminfo->addr, 0, sizeof(wminfo->addr));
  memset(wminfo->length, 0, sizeof(wminfo->length));
  memset(wminfo->n_loaded_pages, 0, sizeof(wminfo->n_loaded_pages));

  // Loop through the process's virtual address space and collect memory map info
  for (va = 0; va < 16; va += PGSIZE) {
    if ((pte = walkpgdir(pgdir, (void *)va, 0)) != 0 && (*pte & PTE_P)) {
        wminfo->addr[total_mmaps] = va;
        wminfo->length[total_mmaps] = PGSIZE;
        wminfo->n_loaded_pages[total_mmaps] = 
        total_mmaps++;
      }
    }
  }

  wminfo->total_mmaps = total_mmaps;
  return SUCCESS;
}

int
sys_getwmapinfo(void)
{
  struct wmapinfo *wminfo;
  if (argptr(0, (void *)&wminfo, sizeof(struct wmapinfo)) < 0)
    return FAILED;

  return getwmapinfo_helper(wminfo);
}

int
va2pa_helper(uint va)
{
  pde_t *pgdir = myproc()->pgdir;
  pte_t *pte;
  uint pa;

  // Check if the virtual address is within the valid range for the current process
  if ((pte = walkpgdir(pgdir, (void *)va, 0)) == 0)
    return -1;  // Page not found

  // Extract the physical address from the PTE
  pa = PTE_ADDR(*pte);

  // Add the offset from the virtual address to the physical address
  return pa + (va % PGSIZE);
}

int
sys_va2pa(void)
{
  uint va;
  if (argint(0, (int *)&va) < 0) {
    return -1;
  }
  return va2pa_helper(va);
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
