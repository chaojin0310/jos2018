/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>



###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */

TRAPHANDLER_NOEC(trap_handler0, T_DIVIDE)
TRAPHANDLER_NOEC(trap_handler1, T_DEBUG)
TRAPHANDLER_NOEC(trap_handler2, T_NMI)
TRAPHANDLER_NOEC(trap_handler3, T_BRKPT)
TRAPHANDLER_NOEC(trap_handler4, T_OFLOW)
TRAPHANDLER_NOEC(trap_handler5, T_BOUND)
TRAPHANDLER_NOEC(trap_handler6, T_ILLOP)
TRAPHANDLER_NOEC(trap_handler7, T_DEVICE)
TRAPHANDLER(trap_handler8, T_DBLFLT)
TRAPHANDLER(trap_handler10, T_TSS)
TRAPHANDLER(trap_handler11, T_SEGNP)
TRAPHANDLER(trap_handler12, T_STACK)
TRAPHANDLER(trap_handler13, T_GPFLT)
TRAPHANDLER(trap_handler14, T_PGFLT)
TRAPHANDLER_NOEC(trap_handler16, T_FPERR)
TRAPHANDLER(trap_handler17, T_ALIGN)
TRAPHANDLER_NOEC(trap_handler18, T_MCHK)
TRAPHANDLER_NOEC(trap_handler19, T_SIMDERR)

/*
 * Lab 3: Your code here for _alltraps
 */

_alltraps:
	pushl %ds
	pushl %es
	pushal

	movl $GD_KD, %eax
	movw %ax, %ds
	movw %ax, %es

	pushl %esp
	call trap
