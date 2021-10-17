// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/pmap.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line

#define MIN_ADDR(x, y) ((x) <= (y) ? (x) : (y))
#define UNIT_LEN 4
#define MAX_MEM 0xffffffff


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display backtrace infomation to help your to debug", mon_backtrace },
	{ "showmapping", "Display all of the physical page mappings applying to a range of virtual address", mon_showmapping },
	{ "setperm", "Explicitly set permissions of any mapping.", mon_setperm },
	{ "dumpmem", "Dump the contents of a range of memory (va/pa).", mon_dumpmemory }, 
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
    // Get the current ebp pointing to the stack top.
	uint32_t *ebp = (uint32_t *)read_ebp();
	uint32_t eip;
	struct Eipdebuginfo info;

	cprintf("Stack backtrace:\n");
	while (ebp) {
		eip = *(ebp + 1);
        // Print demanded content according to the stack structure known before.
		cprintf("  ebp %08x  eip %08x  args %08x %08x %08x %08x %08x\n", 
				ebp, eip, *(ebp + 2), *(ebp + 3), *(ebp + 4), *(ebp + 5), *(ebp + 6));
		// Get and print debug infomation.
		// For arguments, notice that uintptr_t == uint32_t
		debuginfo_eip(eip, &info);
		cprintf("         %s:%d: %.*s+%d\n", info.eip_file, info.eip_line, info.eip_fn_namelen, info.eip_fn_name, eip - info.eip_fn_addr);
        // Trace back to the last stack frame.
		ebp = (uint32_t *)(*ebp);
	}
	return 0;
}

// Turn a hex string(%x) to an uint
uint32_t hex2uint(char *xbuf) {
	uint32_t sum = 0;
	xbuf += 2; // skip the '0x'
	while (*xbuf != '\0') {
		sum <<= 4; // sum *= 16
		// treat any unknown char to '0'
		if (*xbuf >= 'a' && *xbuf <= 'f')
			sum += *xbuf -'a' + 10;
		else if (*xbuf >= '0' && *xbuf <= '9')
			sum += *xbuf - '0';
		xbuf++;
	}
	return sum;
}

// Turn a decimal string(%d) to an uint
uint32_t dec2uint(char *xbuf) {
	uint32_t sum = 0;
	while (*xbuf != '\0') {
		sum *= 10;
		// treat any unknown char to '0'
		if (*xbuf >= '0' && *xbuf <= '9')
			sum += *xbuf - '0';
		xbuf++;
	}
	return sum;
}

// Print pte's PA and permissions in a beautiful format
void print_pte(pte_t *pte) {
	// cprintf("%x %x\n", pte, *pte);
	if (pte && (*pte & PTE_P)) {
		cprintf("PA: 0x%08x\tPTE_W: %d\tPTE_U: %d\n", 
				PTE_ADDR(*pte), !!(*pte & PTE_W), !!(*pte & PTE_U));
	}
	else if ((uint32_t)pte == (uint32_t)kern_pgdir) { // corner case
		cprintf("PA: 0x%08x\tPTE_W: 0\tPTE_U: 0\n", PADDR(kern_pgdir));
	}
	else {
		cprintf("PA: No Mapping\n");
	}
}

int
mon_showmapping(int argc, char **argv, struct Trapframe *tf) {
	if (argc != 3) {
		cprintf("usage: showmapping 0x<start_addr> 0x<end_addr>\n");
		return 0;
	}
	uint32_t start_addr = hex2uint(argv[1]);
	uint32_t end_addr = hex2uint(argv[2]);
	// Make sure they are page's first addresses
	start_addr = ROUNDDOWN(start_addr, PGSIZE);
	end_addr = ROUNDDOWN(end_addr, PGSIZE);
	cprintf("start_addr: %08x\tend_addr: %08x\n", start_addr, end_addr);
	for (; start_addr <= end_addr; start_addr += PGSIZE) {
		pte_t *pte = pgdir_walk(kern_pgdir, (void *)start_addr, 0);
		cprintf("VA: 0x%08x\t", start_addr);
		print_pte(pte);
	}
	return 0;
}

int
mon_setperm(int argc, char **argv, struct Trapframe *tf) {
	if (argc != 3) {
		cprintf("usage: setperm 0x<virtual address> 0x<permission>\n");
		cprintf("permission: PTE_U=0x4, PTE_W=0x2, Clear=0x0, use | to combine bits\n");
		return 0;
	}
	uint32_t va = hex2uint(argv[1]);
	uint32_t perm = hex2uint(argv[2]);
	perm &= 0xfff; // make sure it is only permission

	pte_t *pte = pgdir_walk(kern_pgdir, (void *)va, 0);
	if (pte && (*pte & PTE_P)) {
		*pte = (*pte & ~0xfff) | perm | PTE_P;
		cprintf("Permission 0x%08x has been set at 0x%08x\n", perm, va);
	}
	else {
		cprintf("There's no mapping at 0x%08x\n", va);
	}
	return 0;
}


// dump memory indicated by physical address
// n bytes starting at start_pa
static void dump_physmem(uint32_t start_pa, uint32_t n) {
	// Do not handle uint32 overflow
	// At most 256MB above KERNBASE
	if ( start_pa + n > npages * PGSIZE) {
		cprintf("Range out of memory!\n");
		return;
	}
	uint32_t end_pa = start_pa + n;
	uint32_t next_addr = MIN_ADDR(end_pa, MAX_MEM - KERNBASE + 1);
	for (; start_pa < next_addr; start_pa += 4) {
		cprintf("PA: 0x%08x\tContent: %02x\n", start_pa, *(uint32_t *)KADDR(start_pa));
	}
}


// dump memory indicated by virtual address
// n bytes starting at start_va
static void dump_virtmem(uint32_t start_va, uint32_t n) {
	// Do not handle uint32 overflow
	uint32_t end_va = start_va + n;
	uint32_t next_addr; // lasting to one pte ends
	pte_t *pte;

	while (start_va < end_va) {
		pte = pgdir_walk(kern_pgdir, (void *)start_va, 0);
		if (!pte) {
			// pass a pde (4MB)
			next_addr = MIN_ADDR(end_va, (uint32_t)(PGADDR(PDX(start_va) + 1, 0, 0)));
			for (; start_va < next_addr; start_va += UNIT_LEN) {
				cprintf("VA: 0x%08x\tPA: No mapping\tContent: None\n", start_va);
			}
		}
		else if (!(*pte & PTE_P)) {
			// pass a pte (4KB)
			next_addr = MIN_ADDR(end_va, (uint32_t)(PGADDR(PDX(start_va), PTX(start_va) + 1, 0)));
			for (; start_va < next_addr; start_va += UNIT_LEN) {
				cprintf("VA: 0x%08x\tPA: No mapping\tContent: None\n", start_va);
			}
		}
		else {
			next_addr = MIN_ADDR(end_va, (uint32_t)(PGADDR(PDX(start_va), PTX(start_va) + 1, 0)));
			for (; start_va < next_addr; start_va += UNIT_LEN) {
				cprintf("VA: 0x%08x\tPA: 0x%08x\tContent: %02x\n", 
						start_va, PTE_ADDR(*pte) | PGOFF(start_va), *(uint32_t *)start_va);
			}
		}
	}
}

int
mon_dumpmemory(int argc, char **argv, struct Trapframe *tf) {
	static const char *help_msg = 
		"usage: dumpmem <p/v> 0x<address> 0x<n: number of 4bytes' memory unit>\n"\
		"p/v: use physical or virtual address\n"\
		"n : display 4n bytes, since we consider 4Bytes as a memory unit\n";
	if (argc != 4) {
		cprintf(help_msg);
		return 0;
	}
	else if (argv[1][0] != 'p' && argv[1][0] != 'v') {
		cprintf(help_msg);
		return 0;
	}

	int phys = 0; // use physical
	if (argv[1][0] == 'p')
		phys = 1; // use virtual

	uint32_t start_addr = hex2uint(argv[2]);
	start_addr = ROUNDDOWN(start_addr, UNIT_LEN); // Since it is a 32-bit OS
	uint32_t n = dec2uint(argv[3]); // decimal input
	n *= UNIT_LEN;
	
	if (phys) {
		dump_physmem(start_addr, n);
	}
	else {
		dump_virtmem(start_addr, n);
	}
	return 0;
}


/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	// int x = 1, y = 3, z = 4;
	// cprintf("x %d, y %x, z %d\n", x, y, z);
	// unsigned int i = 0x00646c72;
    // cprintf("H%x Wo%s", 57616, &i);
	// cprintf("x=%d y=%d", 3);
	// cprintf("%m%s\n%m%s\n%m%s\n", 0x0100, "blue", 0x0200, "green", 0x0400, "red");

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
