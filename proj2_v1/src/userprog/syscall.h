#include <list.h>

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct files{
	int fd;
	struct file *file;
	struct dir *dir;
	struct list_elem elem;
};

void syscall_init (void);

struct lock syscall_lock;

#endif /* userprog/syscall.h */
