#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"
#include "traps.h"
#include "fs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "file.h"
#include "wmap.h"
// Interrupt descriptor table (shared by all CPUs).
struct gatedesc idt[256];
extern uint vectors[];  // in vectors.S: array of 256 entry pointers
struct spinlock tickslock;
uint ticks;

void
tvinit(void)
{
  int i;

  for(i = 0; i < 256; i++)
    SETGATE(idt[i], 0, SEG_KCODE<<3, vectors[i], 0);
  SETGATE(idt[T_SYSCALL], 1, SEG_KCODE<<3, vectors[T_SYSCALL], DPL_USER);

  initlock(&tickslock, "time");
}

void
idtinit(void)
{
  lidt(idt, sizeof(idt));
}

//PAGEBREAK: 41
void
trap(struct trapframe *tf)
{
  if(tf->trapno == T_SYSCALL){
    if(myproc()->killed)
      exit();
    myproc()->tf = tf;
    syscall();
    if(myproc()->killed)
      exit();
    return;
  }

  switch(tf->trapno){
  case T_IRQ0 + IRQ_TIMER:
    if(cpuid() == 0){
      acquire(&tickslock);
      ticks++;
      wakeup(&ticks);
      release(&tickslock);
    }
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE:
    ideintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE+1:
    // Bochs generates spurious IDE1 interrupts.
    break;
  case T_IRQ0 + IRQ_KBD:
    kbdintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_COM1:
    uartintr();
    lapiceoi();
    break;
  case T_IRQ0 + 7:
  case T_IRQ0 + IRQ_SPURIOUS:
    cprintf("cpu%d: spurious interrupt at %x:%x\n",
            cpuid(), tf->cs, tf->eip);
    lapiceoi();
    break;
 case T_PGFLT: {  // Handle Page Fault
    uint fault_addr = rcr2(); // Faulting virtual address
    struct proc *p = myproc();

    // Check if fault_addr is part of a mapped region
    for (int i = 0; i < p->mmap_count; i++) {
      struct mmap_region *mmap = &p->mmap_regions[i];

      if (fault_addr >= mmap->addr && fault_addr < mmap->addr + mmap->length) {
        uint aligned_addr = PGROUNDDOWN(fault_addr); // Align to page boundary

        // Allocate a new physical page
        char *mem = kalloc();
        if (!mem) {
          cprintf("Lazy allocation failed: out of memory\n");
          p->killed = 1;
          break;
        }
        memset(mem, 0, PGSIZE);
        mmap->n_loaded_pages++;
        // Map the physical page to the faulting virtual address
        if (mappages(p->pgdir, (void *)aligned_addr, PGSIZE, V2P(mem), PTE_W | PTE_U) < 0) {
          kfree(mem);
          cprintf("Mapping failed\n");
          p->killed = 1;
          break;
        }
        if(!(mmap->flags & MAP_ANONYMOUS)){
            uint file_offset =aligned_addr-mmap->addr;
            uint bytes_remaining=mmap->addr+mmap->length-aligned_addr;//
            struct file *f =  p->ofile[mmap->fd];
                begin_op();
                ilock(f->ip);
                readi(f->ip, (void*)aligned_addr, file_offset, bytes_remaining);
                iunlock(f->ip);
                end_op();
        }
    
        return; // Successfully handled the page fault
      }
    }

    // If no mapping matches, kill the process
    cprintf("pid %d %s: segmentation fault at 0x%x\n",
            p->pid, p->name, fault_addr);
    p->killed = 1;
    break;
  }
  //PAGEBREAK: 13
  default:
    if(myproc() == 0 || (tf->cs&3) == 0){
      // In kernel, it must be our mistake.
      cprintf("unexpected trap %d from cpu %d eip %x (cr2=0x%x)\n",
              tf->trapno, cpuid(), tf->eip, rcr2());
      panic("trap");
    }
    // In user space, assume process misbehaved.
    cprintf("pid %d %s: trap %d err %d on cpu %d "
            "eip 0x%x addr 0x%x--kill proc\n",
            myproc()->pid, myproc()->name, tf->trapno,
            tf->err, cpuid(), tf->eip, rcr2());
    myproc()->killed = 1;
  }

  // Force process exit if it has been killed and is in user space.
  // (If it is still executing in the kernel, let it keep running
  // until it gets to the regular system call return.)
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();

  // Force process to give up CPU on clock tick.
  // If interrupts were on while locks held, would need to check nlock.
  if(myproc() && myproc()->state == RUNNING &&
     tf->trapno == T_IRQ0+IRQ_TIMER)
    yield();

  // Check if the process has been killed since we yielded
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();
}
