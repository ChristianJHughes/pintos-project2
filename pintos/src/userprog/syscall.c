#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/init.h" // Imports shutdown_power_off() for use in halt()

static void syscall_handler (struct intr_frame *);
static void find_tid (struct thread *t, void * aux);

/* Stores the id of the thread you're searching for when calling the find_tid(). */
static tid_t current_tid;

/* The thread with a tid matching current_tid, determined in find_tid(). */
static struct thread *matching_thread;

/* Creates a struct to insert files and their respective file descriptor into
   the file_descriptors list for the current thread. */
struct thread_file
{
    struct list_elem file_elem;
    struct file *file_addr;
    int file_descriptor;
};

/* Lock is in charge of ensuring that only one process can access the file system at one time. */
struct lock lock_filesys;

void
syscall_init (void)
{
  /* Initialize the lock for the file system. */
  lock_init(&lock_filesys);

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

    /* Stores the physical page pointer. */
    void * phys_page_ptr;

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
				/* The first argument of exec is the entire command line text for executing the program */
				get_stack_arguments(f, &args[0], 1);

        /* Ensures that converted address is valid. */
        phys_page_ptr = (void *) pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
        if (phys_page_ptr == NULL)
        {
          exit(-1);
        }
        args[0] = (int) phys_page_ptr;

        /* Return the result of the exec() function in the eax register. */
				f->eax = exec((const char *) args[0]);
				break;

			case SYS_WAIT:
        /* The first argument is the PID of the child process
           that the current process must wait on. */
				get_stack_arguments(f, &args[0], 1);

        /* Return the result of the wait() function in the eax register. */
				f->eax = wait((pid_t) args[0]);
				break;

			case SYS_CREATE:
        /* The first argument is the name of the file being created,
           and the second argument is the size of the file. */
				get_stack_arguments(f, &args[0], 2);

        /* Ensures that converted address is valid. */
        phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
        if (phys_page_ptr == NULL)
        {
          exit(-1);
        }
        args[0] = (int) phys_page_ptr;

        /* Return the result of the create() function in the eax register. */
        f->eax = create((const char *) args[0], (unsigned) args[1]);
				break;

			case SYS_REMOVE:
        /* The first argument of remove is the file name to be removed. */
        get_stack_arguments(f, &args[0], 1);

        /* Ensures that converted address is valid. */
        phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
        if (phys_page_ptr == NULL)
        {
          exit(-1);
        }
        args[0] = (int) phys_page_ptr;

        /* Return the result of the remove() function in the eax register. */
        f->eax = remove((const char *) args[0]);
				break;

			case SYS_OPEN:
				// puts("halt");
        get_stack_arguments(f, &args[0], 1);

        /* Ensures that converted address is valid. */
        phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
        if (phys_page_ptr == NULL)
        {
          exit(-1);
        }
        args[0] = (int) phys_page_ptr;

        /* Return the result of the remove() function in the eax register. */
        f->eax = open((const char *) args[0]);

				break;

			case SYS_FILESIZE:
				// puts("halt");
				break;

			case SYS_READ:
				// puts("halt");
				break;

			case SYS_WRITE:
        /* Get three arguments off of the stack. The first represents the fd, the second
           represents the buffer, and the third represents the buffer length. */
        get_stack_arguments(f, &args[0], 3);

        /* Ensures that converted address is valid. */
        phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[1]);
        if (phys_page_ptr == NULL)
        {
          exit(-1);
        }
        args[1] = (int) phys_page_ptr;

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
        /* If an invalid system call was sent, terminate the program. */
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
	thread_current()->exit_status = status;
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
/* Executes the program with the given file name. */
pid_t exec (const char *file)
{
  /* If a null file is passed in, return a -1. */
	if(*file == NULL)
	{
		return -1;
	}

  /* Get and return the PID of the process that is created. */
	pid_t child_tid = process_execute(file);
	return child_tid;
}

/* If the PID passed in is our child, then we wait on it to terminate before proceeding */
int wait (pid_t pid)
{
	/* If the thread created is a valid thread, then we must disable interupts, and add it to this threads list of child threads. */
  return process_wait(pid);
}

/* Creates a file of given name and size, and adds it to the existing file system. */
bool create (const char *file, unsigned initial_size)
{
  lock_acquire(&lock_filesys);
  bool file_status = filesys_create(file, initial_size);
  lock_release(&lock_filesys);
  return file_status;
}

/* Remove the file from the file system, and return a boolean indicating
   the success of the operation. */
bool remove (const char *file)
{
  lock_acquire(&lock_filesys);
  bool was_removed = filesys_remove(file);
  lock_release(&lock_filesys);
  return was_removed;
}

/* Opens a file with the given name, and returns the file descriptor assigned by the
   thread that opened it. Inspiration derived from GitHub user ryantimwilson (see
   Design2.txt for attribution link). */
int open (const char *file)
{
  /* Make sure that only one process can get ahold of the file system at one time. */
  lock_acquire(&lock_filesys);
  struct file* f = filesys_open(file);
  /* If no file was created, then return -1. */
  if(f == NULL)
  {
    lock_release(&lock_filesys);
    return -1;
  }

  /* Create a struct to hold the file/fd, for use in a list in the current process.
     Increment the fd for future files. Release our lock and return the fd as an int. */
  struct thread_file *new_file = malloc(sizeof(struct thread_file));
  new_file->file_addr = f;
  int fd = thread_current ()->cur_fd;
  thread_current ()->cur_fd++;
  new_file->file_descriptor = fd;
  list_push_front(&thread_current ()->file_descriptors, &new_file->file_elem);
  lock_release(&lock_filesys);
  return fd;
}


int filesize (int fd) {return 0;}
int read (int fd, void *buffer, unsigned length) {return 0;}
void seek (int fd, unsigned position) {}
unsigned tell (int fd) {return 0;}
void close (int fd) {}

/* Check to make sure that the given pointer is in user space,
   and is not null. We must exit the program and free its resources should
   any of these conditions be violated. */
void check_valid_addr (const void *ptr_to_check)
{
  /* Terminate the program with an exit status of -1 if we are passed
     an argument that is not in the user address space or is null. Also make
     sure that pointer doesn't go beyond the bounds of virtual address space.  */
  if(!is_user_vaddr(ptr_to_check) || ptr_to_check == NULL || ptr_to_check < 0x08084000) // TODO IDK
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

/* This function is passed to thread_foreach in order to find the thread
   that matches a specific tid. */
static void find_tid (struct thread *t, void * aux)
{
  if(current_tid == t->tid)
  {
    matching_thread = t;
  }
}
