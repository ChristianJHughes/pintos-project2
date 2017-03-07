#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/init.h" // Imports shutdown_power_off() for use in halt()

static uint32_t *active_pd (void);

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

	if(is_kernel_vaddr(f->esp) && f->esp == NULL && !pagedir_get_page(active_pd(), f->esp)) // TODO The active_pd might not be correct.
	{
		// Terminate and Free Resources
		puts("WHOOPS");
	} 
	else
	{
		// Get the value of the system call (based on enum) and call corresponding syscall function.
		switch(*(int *) f->esp)
		{
			case SYS_HALT:
				puts("HALT");
				halt();
				break;

			case SYS_EXIT:
				puts("EXIT");
				// Get a pointer to the next argument on the stack, which is the exit code.
				int * status = (int *) f->esp + 1;
				// We pass exit the status code of the process.
				exit(*status);
				break;
			
			case SYS_EXEC:
				// puts("halt");
				break;
			
			case SYS_WAIT:
				// puts("halt");
				break;
			
			case SYS_CREATE:
				// puts("halt");
				break;
			
			case SYS_REMOVE:
				// puts("halt");
				break;
			
			case SYS_OPEN:
				// puts("halt");
				break;
			
			case SYS_FILESIZE:
				// puts("halt");
				break;
			
			case SYS_READ:
				// puts("halt");
				break;
			
			case SYS_WRITE:
				puts("WRITE");
				int * fd = (int *) f->esp + 1;
				int * buf = (int *) f->esp + 2;
				int * len = (int *) f->esp + 3;
				write(*fd, (const void *) buf, (unsigned) len);
				break;
			
			case SYS_SEEK:
				// puts("halt");
				break;
			
			case SYS_TELL:
				// puts("halt");
				break;
			
			case SYS_CLOSE:
				// puts("halt");
				break;

			default:
				puts("default");
				break;
		}
	}
}

// Terminates Pintos (bummer).
void halt (void)
{
	shutdown_power_off();
}

// Terminates the current user program and returns the status to the kernel.
void exit (int status) 
{
	printf("%s: exit(%d)\n", thread_current()->name, status);
  	thread_exit ();
}

/* Writes LENGTH bytes from BUFFER to the open file FD. Returns the number of bytes actually written,
 which may be less than LENGTH if some bytes could not be written. */
int write (int fd, const void *buffer, unsigned length)
{
	if(fd == 1)
	{
		putbuf(buffer, length);
	} 
	else
	{
		// do something else with other fd
	}

}


pid_t exec (const char *file) {return 0;}
int wait (pid_t pid) {return 0;}
bool create (const char *file, unsigned initial_size) {return true;}
bool remove (const char *file) {return true;}
int open (const char *file) {return 0;}
int filesize (int fd) {return 0;}
int read (int fd, void *buffer, unsigned length) {return 0;}
void seek (int fd, unsigned position) {}
unsigned tell (int fd) {return 0;}
void close (int fd) {}

