#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"

/* File system lock declared and initialized in thread.c because thread_exit
   also must use the lock to close any files not closed with a system call */
extern struct lock fs_lock;

static void syscall_handler (struct intr_frame *);

static void sys_halt (void);
static tid_t sys_exec (const char *cmd_line);
static int sys_wait (tid_t pid);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_exit (int status);
static int sys_open (const char *file);
static void sys_close (int fd);

static void check_ptr (const void *ptr);
static void *get_arg_ptr (void *esp, int n);
static struct file_fd *get_file_fd (int fd);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int *sys_call;

  int *status;

  int *fd;
  const char **buf;
  int *size;

  const char **file;

  tid_t *pid;

  const char **cmd_line;

  unsigned *initial_size;

  unsigned *position;

  void **buffer;

  sys_call = (int*) f->esp;
  check_ptr(sys_call);

  switch(*sys_call) {
  case SYS_HALT:
    sys_halt ();
    break;
  case SYS_EXIT:
    status = (int *) get_arg_ptr (f->esp, 1);
    sys_exit(*status);
    NOT_REACHED();
    break;
  case SYS_EXEC:
    cmd_line = (const char **) get_arg_ptr (f->esp, 1);
    f->eax = sys_exec (*cmd_line);
    break;
  case SYS_WAIT:
    pid = (tid_t *) get_arg_ptr (f->esp, 1);
    f->eax = sys_wait (*pid);
    break;
  case SYS_CREATE:
    file = (const char **) get_arg_ptr (f->esp, 1);
    initial_size = (unsigned *) get_arg_ptr (f->esp, 2);
    f->eax = sys_create (*file, *initial_size);
    break;
  case SYS_REMOVE:
    file = (const char **) get_arg_ptr (f->esp, 1);
    f->eax = sys_remove (*file);
    break;
  case SYS_OPEN:
    file = (const char **) get_arg_ptr(f->esp, 1);
    f->eax = sys_open (*file);
    break;
  case SYS_FILESIZE:
    fd = (int *) get_arg_ptr (f->esp, 1);
    f->eax = sys_filesize (*fd);
    break;
  case SYS_READ:
    fd = (int *) get_arg_ptr (f->esp, 1);
    buffer = (void **) get_arg_ptr (f->esp, 2);
    size = (int *) get_arg_ptr (f->esp, 3);
    f->eax = sys_read (*fd, *buffer, *size);
    break;
  case SYS_WRITE:
    fd = (int *) get_arg_ptr (f->esp, 1);
    buf = (const void **) get_arg_ptr (f->esp, 2);
    size = (int *) get_arg_ptr (f->esp, 3);
    f->eax = sys_write (*fd, *buf, *size);
    break;
  case SYS_SEEK:
    fd = (int *) get_arg_ptr (f->esp, 1);
    position = (unsigned *) get_arg_ptr (f->esp, 2);
    sys_seek (*fd, *position);
    break;
  case SYS_TELL:
    fd = (int *) get_arg_ptr (f->esp, 1);
    f->eax = sys_tell (*fd);
    break;
  case SYS_CLOSE:
    fd = (int *) get_arg_ptr (f->esp, 1);
    sys_close (*fd);
    break;
  default:
    printf ("Unrecognized system call!\n");
    thread_exit ();
  }
}


/* Shuts down the system completely */
static void
sys_halt ()
{
  shutdown_power_off ();
  NOT_REACHED ();
}

/* Creates a new process running the program specified in cmd_line,
   and returns the pid (which maps one-to-one to the thread's tid) of
   the new process or -1 if the process could not be successfully loaded.  
   Will not return until the child has completed loading */
static tid_t
sys_exec (const char *cmd_line)
{
  tid_t tid = 0;
  check_ptr (cmd_line);
  
  lock_acquire (&fs_lock);
  tid = process_execute (cmd_line);
  lock_release (&fs_lock);
  sema_down (&thread_current ()->exec_sema);
  if (thread_current ()->child_successful) {
    thread_current ()->child_successful = false;
    return tid;
  }
  return -1;
}

/* Creates a new file in the file system with the name file that is
   initial_size bytes long.  Returns a bool indicating if the file
   creation was successful */
static bool
sys_create (const char *file, unsigned initial_size)
{
  bool success;

  check_ptr (file);
  
  lock_acquire (&fs_lock);
  success = filesys_create (file, initial_size);
  lock_release (&fs_lock);
  
  return success;
}

/* Tries to remove the file with name "file" from the filesystem and returns
   whether or not the remove was successful.  A removed file will remain
   usable in any process that has it open when it is removed, until that 
   process closes the file */
static bool
sys_remove (const char *file)
{
  bool success;

  check_ptr (file);

  lock_acquire (&fs_lock);
  success = filesys_remove (file);
  lock_release (&fs_lock);

  return success;
}

/* Returns the size in bytes of the file with descriptor fd.
   If no file is open with descriptor fd or if the filesize could not be
   read for any other reason, returns -1 */
static int
sys_filesize (int fd)
{
  struct file_fd *ffd = get_file_fd (fd);
  int length;

  if (ffd == NULL)
    return -1;

  lock_acquire (&fs_lock);
  length = file_length (ffd->file);
  lock_release (&fs_lock);

  return length;
}

/* Reads up to size bytes from the file open with descriptor fd into buffer,
   and returns the actual number of bytes read (may be less than size if EOF
   is reached), or -1 if no file is open as fd, or the read fails for any
   other reason.  Calling read with fd = 0 will read input from standard input,
   blocking until size bytes have been read */
static int
sys_read (int fd, void *buffer, unsigned size)
{
  check_ptr (buffer);
  
  unsigned read;
  struct file_fd *ffd;
  char *char_buffer = buffer;

  switch (fd) {
  case 0:
    for (read = 0; read < size; read++) {
      char_buffer[read] = input_getc ();
    }
    return read;
  case 1:
    return -1;
  case 2:
    return -1;
  default:
    ffd = get_file_fd (fd);
    if (ffd == NULL)
      return -1;
    lock_acquire (&fs_lock);
    read = file_read (ffd->file, buffer, size);
    lock_release (&fs_lock);
    return read;
  }
}

/* Writes up to size bytes from buffer to the file open with descriptor fd,
   and returns the actual number written (may be less than size if EOF is 
   reached), or -1 if no file is open as fd or the write fails for another
   reason.  Writing to 1 will print to standard output */
static int 
sys_write (int fd, const void *buffer, unsigned size) 
{
  int written;
  struct file_fd *ffd;
  
  check_ptr (buffer);
  
  switch (fd) {
  case 0:
    return 0;
  case 1:
    putbuf ((char *) buffer, size);
    return size;
  case 2:
    return 0;
  default:
    ffd = get_file_fd (fd);
    if (ffd == NULL)
      return 0;
    
    lock_acquire (&fs_lock);
    written = file_write (ffd->file, buffer, size);
    lock_release (&fs_lock);
    return written;
  }
}

/* Moves the current pointer of the file open as fd to position bytes ahead of
   the start of the file.  Does nothing if no file is open as fd */
static void 
sys_seek (int fd, unsigned position)
{
  struct file_fd *ffd;
  
  ffd = get_file_fd (fd);
  if (ffd == NULL)
    return;
  lock_acquire (&fs_lock);
  file_seek (ffd->file, position);
  lock_release (&fs_lock);
}

/* Returns the number of bytes ahead of the start of the file the current 
   pointer is for the file open as fd, or -1 if no file is open as fd or the
   tell fails for any other reason */
static unsigned
sys_tell (int fd)
{
  unsigned next_byte;
  struct file_fd *ffd;

  ffd = get_file_fd (fd);

  if (ffd == NULL)
    // Proper error value?
    return -1;

  lock_acquire (&fs_lock);
  next_byte = file_tell (ffd->file);
  lock_release (&fs_lock);

  return next_byte;
}

/* Exits the current process with status "status", and prints out the 
   current process's name and exit status */
static void 
sys_exit (int status) 
{
  char* save_ptr;
  char* name = strtok_r(thread_name(), " ", &save_ptr);
  printf("%s: exit(%d)\n", name, status);
  thread_exit_status (status);
  NOT_REACHED();
}

/* Waits for the child with pid "pid" to exit and then returns its exit
   status.  Returns -1 if the process is not this process's child, no process
   exists with pid "pid", or the child has already been successfully waite on */
static int
sys_wait (tid_t pid)
{
  return process_wait (pid);
}

/* Opens the file with the name "file", and returns its file descriptor.
   Returns -1 if no such file exists, or if the open fails for any other
   reason.  If the same file is opened multiple times by separate processes
   or the same process, different fds with separate file pointers will be
   returned */
static int 
sys_open (const char *file)
{
  struct file *f;
  struct file_fd *ffd;
  check_ptr (file);
  
  lock_acquire (&fs_lock);
  f = filesys_open (file);
  lock_release (&fs_lock);

  if (f == NULL)
    return -1;
  ffd = malloc (sizeof(struct file_fd));
  ffd->file = f;
  ffd->fd = thread_current ()->next_fd++;
  list_push_back (&thread_current ()->open_files, &ffd->elem);

  return ffd->fd;
}

/* Closes the file open with file descriptor fd, or does nothing if no
   such file exists */
static void
sys_close (int fd) 
{ 
  struct file_fd *ffd = get_file_fd (fd);
 
  if (ffd == NULL)
    return;
  else {
    list_remove (&ffd->elem);
    
    lock_acquire (&fs_lock);
    file_close (ffd->file);
    lock_release (&fs_lock);

    free (ffd);
  }
}


/* Checks a pointer provided by the user to make sure that it is not null,
   it does not point to kernel memory, and it is contained in a valid page.
   If not, frees the process's resources and exits the thread */
static void 
check_ptr (const void *ptr)
{
  if ( ptr == NULL
       || ptr + sizeof (ptr) >= PHYS_BASE
       || pagedir_get_page (thread_current ()->pagedir, ptr) == NULL
       || pagedir_get_page (thread_current ()->pagedir, 
			    ptr+sizeof (ptr)) == NULL ) {
    sys_exit (-1);
    NOT_REACHED ();
  }
  
}

/* Gets the nth argument (starting with 1) to the system call off the stack,
   and verifies the pointer to make sure it is valid */
static void *
get_arg_ptr (void *esp, int n)
{
  void *result;
  result = (esp+(n*4));
  check_ptr (result);
  return result;
}


/* Get the file_fd struct matching the given file descriptor, or NULL if there
   is no file_fd that matches */
static struct file_fd *
get_file_fd (int fd)
{
  struct thread *t = thread_current ();
  struct list_elem *e;
  
  for (e = list_begin (&t->open_files); e != list_end (&t->open_files);
       e = list_next (e)) {
    struct file_fd *ffd = list_entry (e, struct file_fd, elem);
    if (ffd->fd == fd) 
      return ffd;
  }
  
  return NULL;
}
