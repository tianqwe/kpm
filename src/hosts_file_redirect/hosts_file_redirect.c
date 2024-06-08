/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2024 skkk. All Rights Reserved.
 */

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <asm/ptrace.h>

#include <kpm_utils.h>
#include <kpm_hook_utils.h>

KPM_NAME("page_fault_bypass");
KPM_VERSION("1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("skkk");
KPM_DESCRIPTION("Bypass page fault detection");

typedef void (*do_page_fault_t)(struct pt_regs *, unsigned long);
static do_page_fault_t original_do_page_fault;

hook_func_def(do_page_fault, void, struct pt_regs *regs, unsigned long error_code);
hook_func_no_info(do_page_fault);

static void hook_replace(do_page_fault)(struct pt_regs *regs, unsigned long error_code) {
    printk(KERN_INFO "Bypassing page fault detection\n");
    // Optionally handle the fault here
}

static inline bool installHook() {
    bool ret = false;

    original_do_page_fault = (do_page_fault_t)kallsyms_lookup_name("do_page_fault");
    if (!original_do_page_fault) {
        printk(KERN_ERR "Could not find do_page_fault symbol\n");
        return false;
    }

    hook_install(do_page_fault);
    if (!hook_success(do_page_fault)) {
        printk(KERN_ERR "Failed to install do_page_fault hook\n");
        return false;
    }

    printk(KERN_INFO "Page fault detection hook installed\n");
    ret = true;

    return ret;
}

static inline bool uninstallHook() {
    if (hook_success(do_page_fault)) {
        unhook((void *)hook_original(do_page_fault));
        hook_err(do_page_fault) = HOOK_NOT_HOOK;
        printk(KERN_INFO "Page fault detection hook removed\n");
    } else {
        printk(KERN_INFO "Page fault detection hook was not installed\n");
    }
    return true;
}

static inline void printInfo() {
    printk(KERN_INFO "Kernel Version: %x\n", kver);
    printk(KERN_INFO "Kernel Patch Version: %x\n", kpver);
}

static inline bool pf_control(bool enable) {
    return enable ? installHook() : uninstallHook();
}

static long page_fault_bypass_init(const char *args, const char *event, void *__user reserved) {
    long ret = 0;

    printInfo();
    printk(KERN_INFO "Initializing page fault bypass...\n");

    if (pf_control(true)) {
        printk(KERN_INFO "Initialization successful!\n");
    } else {
        ret = 1;
        printk(KERN_INFO "Initialization failed!\n");
    }

    return ret;
}

static long page_fault_bypass_control0(const char *args, char *__user out_msg, int outlen) {
    if (args) {
        if (strncmp(args, "enable", 6) == 0) {
            writeOutMsg(out_msg, &outlen, pf_control(true) ? "Page fault bypass enabled!" : "Enable failed!");
        } else if (strncmp(args, "disable", 7) == 0) {
            writeOutMsg(out_msg, &outlen, pf_control(false) ? "Page fault bypass disabled!" : "Disable failed!");
        } else {
            printk(KERN_INFO "Control error, args=%s\n", args);
            writeOutMsg(out_msg, &outlen, "Control error!");
            return -1;
        }
    }
    return 0;
}

static long page_fault_bypass_exit(void *__user reserved) {
    uninstallHook();
    printk(KERN_INFO "Exiting page fault bypass...\n");
    return 0;
}

KPM_INIT(page_fault_bypass_init);
KPM_CTL0(page_fault_bypass_control0);
KPM_EXIT(page_fault_bypass_exit);
