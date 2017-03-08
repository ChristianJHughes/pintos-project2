#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/init.h" // Imports shutdown_power_off() for use in halt()

static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Handles a system call initiated by a user program. */
static void
syscall_handler (struct intr_frame *f UNUSED)
{
    /* First ensure that the system call argument is a valid address. If not, exit immediately. */
    check_valid_addr((const void *) f->esp);

    /* Holds the stack arguments that directly follow the system call. */
    int args[3];

		/* Get the value of the system call (based on enum) and call corresponding syscall function. */
		switch(*(int *) f->esp)
		{
			case SYS_HALT:
        /* Call the halt() function, which requires no arguments */
				halt();
				break;

			case SYS_EXIT:
        /* Exit has exactly one stack argument, representing the exit status. */
        get_stack_arguments(f, &args[0], 1);
				/* We pass exit the status code of the process. */
				exit(args[0]);
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

        /* Get three arguments off of the stack. The first represents the fd, the second
           represents the buffer, and the third represents the buffer length. */
        get_stack_arguments(f, &args[0], 3);

        /* Transform the virtual address for the buffer into a physical address. */
        args[1] = (int) pagedir_get_page(thread_current()->pagedir, (const void *) args[1]);

        /* Return the result of the write() function in the eax register. */
        f->eax = write(args[0], (const void *) args[1], (unsigned) args[2]);
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
        // If an invalid system call was sent, terminate the program.
				exit(-1);
				break;
		}
}

/* Terminates Pintos, shutting it down entirely (bummer). */
void halt (void)
{
	shutdown_power_off();
}

/* Terminates the current user program. It's exit status is printed,
   and its status returned to the kernel. */
void exit (int status)
{
	printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit ();
}

/* Writes LENGTH bytes from BUFFER to the open file FD. Returns the number of bytes actually written,
 which may be less than LENGTH if some bytes could not be written. */
int write (int fd, const void *buffer, unsigned length)
{
  /* If fd is equal to one, then we write to STDOUT (the console, usually). */
	if(fd == 1)
	{
		putbuf(buffer, length);
    return length;
	}
	else
	{
		/* do something else with other fd */
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

/* Check to make sure that the given pointer is not in kernel space,
   is not null, and is not an valid page. We must exit the program
   and free its resources should any of these conditions be violated. */
void check_valid_addr (const void *ptr_to_check)
{
  if(is_kernel_vaddr(ptr_to_check) || ptr_to_check == NULL || !pagedir_get_page(thread_current()->pagedir, ptr_to_check))
	{
    /* Terminate the program and free its resources */
    exit(-1);
	}
}

/* Code inspired by GitHub Repo created by ryantimwilson (full link in Design2.txt).
   Get up to three arguments from a programs stack (they directly follow the system
   call argument). */
void get_stack_arguments (struct intr_frame *f, int *args, int num_of_args)
{
  int i;
  int *ptr;
  for (i = 0; i < num_of_args; i++)
    {
      ptr = (int *) f->esp + i + 1;
      check_valid_addr((const void *) ptr);
      args[i] = *ptr;
    }
}
