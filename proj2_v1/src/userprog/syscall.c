#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);
int write (int fd, const void *buffer, unsigned size);
void exit(int status);
void halt(void);
bool validate_ptr(void *addr);
bool create(const char* file, unsigned initial_size);
int open(const char* file);

void
syscall_init (void) 
{
  lock_init(&syscall_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

struct file*
get_file(int fd)
{
  struct thread *t = thread_current();
  struct list_elem *e;
  for(e = list_begin(&t->file_list); e !=list_end(&t->file_list); e = list_next(e))
  {
    if(fd == list_entry(e, struct files, elem)->fd)
      return list_entry(e, struct files, elem)->file;
  }
  return NULL;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call! %d\n", *(int*)f->esp);
switch(*(int*)f->esp)
  {
case SYS_HALT:
	{
		halt();
		break;
	}
case SYS_EXIT:
      {
        //Implement syscall
      	void* arg = (void*)(*((int*)f->esp + 1));
      	if(!validate_ptr(arg)){
      		exit(-1);
        	break;
      	}
        //verify
        int status = *((int*)f->esp + 1);
        exit(status);
        break; 
      }
case SYS_WRITE:
      {
        //Implement syscall 
        int fd = *((int*)f->esp + 1);
        void* buffer = (void*)(*((int*)f->esp + 2));
        unsigned size = *((unsigned*)f->esp + 3);
        
        f->eax = write(fd, buffer, size);
        break; 
      }
case SYS_CREATE:
      {
      	const char *file = (const char *)(*((int*)f->esp + 1));
      	unsigned size = *((unsigned*)f->esp + 2);
      	f->eax = create(file,size);
      }
case SYS_OPEN:
      {
      	const char *file = (const char *)(*((int*)f->esp + 1));
      	f->eax = open(file);
      }

}
}
bool validate_ptr(void *addr){
	if( !is_user_vaddr(addr) ){
		return 0;
	}

	return 1;
}

bool create(const char* file, unsigned initial_size){
	//printf("size: %d\n", strlen(file));
  //printf("FILE IS <%s>\n", file);

	if(!is_user_vaddr((void*)file) || (void*)file == NULL){
		exit(-1);
		return 0;
	} 
	
  // Passes create-empty
  if( strlen(file) == 0 ){
    exit(-1);
    return 0;
  }

  // Attempt to open file to see if exists
  int file_exists = open(file);
  if( file_exists != -1 ){
    struct thread *t = thread_current();
    struct list_elem *l;
    for(l = list_begin(&t->file_list); l != list_end(&t->file_list); l = list_next(l)){
      // compare fds with file_exists
    }
  }

  lock_acquire(&syscall_lock);
	if( filesys_create(file, initial_size) )
  {
    lock_release(&syscall_lock);
    return 1;
  }
  else{
    //exit(-1);
    lock_release(&syscall_lock);
    return 0;
  }
}

int open(const char* file){

	if(!is_user_vaddr((void*)file) || (void*)file == NULL){
		exit(-1);
		return -1;
	} 

  //printf("size: %u\n", initial_size);
  lock_acquire(&syscall_lock);
  struct file *open_file = filesys_open(file);
  lock_release(&syscall_lock);

  if(open_file == NULL){  
    return -1;
  }

  // Grab thread's fd data
  struct thread *t = thread_current();
  int new_fd = t->num_fds;

  struct files *this_file = palloc_get_page(0);
   if(this_file == NULL){
     return -1;
   }

  this_file->file = open_file;
  this_file->fd = new_fd;
  t->num_fds++;
  list_push_back(&t->file_list, &this_file->elem);

	return new_fd;
}

void halt(void){
	shutdown_power_off();
}

void exit(int status){
  printf("%s: exit(%d)\n",thread_current()->name,status);
  thread_exit();
}

int write (int fd, const void *buffer, unsigned size){
  if(fd == 1){
    putbuf(buffer,size);
    return size;
  }
  return 0;
}

int filesize(int fd){
  char buf[4096] = "";
  int read_status;

  //read_status = read(fd, buf, 4096);

  return read_status;  
}