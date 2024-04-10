/*
 * Hooking kernel functions using ftrace framework
 *
 * Copyright (c) 2018 ilammy
 */

#define pr_fmt(fmt) "ftrace_hook: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>

MODULE_DESCRIPTION("Example module hooking clone() and execve() via ftrace with path translation");
MODULE_AUTHOR("ilammy <a.lozovsky@gmail.com>, gns <gleb.semenov@gmail.com>");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

struct translation_blob {
    char *lookup_buffer;
    char *kernel_filename;
    char* abspath;
    int empty;
} translation_blob_t;

int translate_filename(translation_blob_t *tb, int dfd,
                       const char __user *filename)
{
    int rv;
    int lookup_flags =
        LOOKUP_FOLLOW | LOOKUP_DOWN | LOOKUP_MOUNTPOINT | LOOKUP_PARENT;
    struct path path;

    tb->lookup_buffer = __getname();
    if(!tb->lookup_buffer) return -ENOMEM;


    rv = user_path_at_empty(dfd, filename, lookup_flags, &path, &tb->empty);
    if (!rv) tb->abspath = d_path(&path, tb->lookup_buffer, PATH_MAX);
    path_put(&path);

    if (tb->abspath) return 0;

    stncpy_from_user(tb->lookup_buffer, filename, PATH_MAX);
    if(tb->lookup_buffer[0] == '/') {
        /* it looks like we have absolute path */
        tb->abspath = tb->lookup_buffer;
        return 0;
    }








    return rv;

}


int check_filename(const char* caller, int dfd, const char __user *filename) {
    int lookup_flags =
        LOOKUP_FOLLOW | LOOKUP_DOWN | LOOKUP_MOUNTPOINT | LOOKUP_PARENT;
    char *lookup_buffer = NULL;
    char *pwd_buf = NULL;
    char *kernel_filename = NULL;
    char *abspath = NULL;
    struct path path;
    int empty;
    int rv = 0;

    lookup_buffer = __getname();
    if(!lookup_buffer) return -ENOMEM;

    rv = user_path_at_empty(dfd, filename, lookup_flags, &path, &empty);
    if (!rv) abspath = d_path(&path, lookup_buffer, PATH_MAX);
    path_put(&path);

    if(abspath)
        pr_info("%s:%s: abspath: %s\n", caller, __func__, abspath);
    else {
        /* relative or non-existent path */
        kernel_filename = __getname();
        if(!kernel_filename) {
            rv = -ENOMEM;
            goto out;
        }

        stncpy_from_user(kernel_filename, filename, PATH_MAX);
        if (kernel_filename[0] == '/') {
            pr_info("%s:%s: non-existent absolute filename given: %s\n", caller, __func__, kernel_filename);
        }
        else if (dfd == AT_FDCWD) {
            /* relative filename */
            char *pwd_path;
            pwd_buf = __getname();
            if (!pwd_buf) {
                rv = -ENOMEM;
                goto out;
            }
            get_fs_pwd(current->fs, &path);
            pwd_path = dentry_path_raw(path.dentry, pwd_buf, PATH_MAX);
            path_put(&path);
            strcpy(lookup_buffer, pwd_path);
            strcat(lookup_buffer, "/");
            strcat(lookup_buffer, kernel_filename);

        }




      /* try to construct full path */
      char *pwd_path;

      buf = __getname();
      if (!buf) {
        rv = -ENOMEM;
        goto out;
        }

        get_fs_pwd(current->fs, &path);
        pwd_path = dentry_path_raw(path.dentry, buf, PATH_MAX);
        if ((rv = IS_ERR(pwd_path))) {
            pr_err("dentry_path_raw failed: %li", PTR_ERR(pwd_path));
            path_put(&path);
            goto out;
        } else {

            pr_info("%s:%s: Full path: %s",  caller, __func__, full_path);
        }
        path_put(&path);
        __putname(buf);
    }
out:
    __putname(lookup_buffer);
    if (kernel_filename) __putname(kernel_filename);
    if (pwd_buf) __putname(pwd_buf);

    return rv;
}

#ifdef PTREGS_SYSCALL_STUBS

static asmlinkage long (*real_sys_clone)(struct pt_regs *regs);
static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);
static asmlinkage long (*real_sys_execveat)(struct pt_regs *regs);
static asmlinkage long (*real_sys_open)(struct pt_regs *regs);
static asmlinkage long (*real_sys_openat)(struct pt_regs *regs);
static asmlinkage long (*real_sys_mkdir)(struct pt_regs *regs);
static asmlinkage long (*real_sys_mkdirat)(struct pt_regs *regs);
static asmlinkage long (*real_sys_creat)(struct pt_regs *regs);

static asmlinkage long fh_sys_clone(struct pt_regs *regs) {
	long ret;

	pr_info("clone() before\n");
	ret = real_sys_clone(regs);
	pr_info("clone() after: %ld\n", ret);
	return ret;
}

static asmlinkage long fh_sys_execve(struct pt_regs *regs) {
    long ret;

    check_filename("fh_sys_execve", AT_FDCWD, (void*)regs->di);

    ret = real_sys_execve(regs);
    pr_info("execve() after: %ld\n", ret);

    return ret;
}

/*
  %rax __NR_execveat
  %rdi int dfd
  %rsi const char __user *filename
  %rdx const char __user *const __user *argv
  %r10 const char __user *const __user *envp
  %r8  int flags
*/
static asmlinkage long fh_sys_execveat(struct pt_regs *regs) {
    long ret;

    check_filename("fh_sys_execveat", (int)regs->di, (void*)regs->si);

    ret = real_sys_execveat(regs);
    pr_info("execveat() after: %ld\n", ret);

    return ret;
}

/*
  %rax __NR_open
  %di  const char *filename
  %si  int flags
  %rdx int mode
*/
static asmlinkage long fh_sys_open(struct pt_regs *regs) {
    long ret;

    check_filename("fh_sys_open", AT_FDCWD, (void*)regs->di);

    ret = real_sys_open(regs);
    pr_info("open() after: %ld\n", ret);

    return ret;
}

/*
  %rax __NR_openat
  %rdi int dfd
  %rsi const char *filename
  %rdx int flags
  %r10 int mode
*/
static asmlinkage long fh_sys_openat(struct pt_regs *regs) {
    long ret;

    check_filename("fh_sys_openat", (int)regs->di, (void*)regs->si);

    ret = real_sys_openat(regs);
    if (!ret)
        pr_info("openat() after: %ld\n", ret);

    return ret;
}


/*
  %rax __NR_mkdir
  %di const char *pathname
  %si int mode
*/
static asmlinkage long fh_sys_mkdir(struct pt_regs *regs) {
    long ret;

    check_filename("fh_sys_mkdir", AT_FDCWD, (void*)regs->di);

    ret = real_sys_mkdir(regs);
    pr_info("mkdir() after: %ld\n", ret);

    return ret;
}

/*
  %rax __NR_mkdirat
  %rdi int dfd
  %rsi const char *pathname
  %rdx int mode
*/
static asmlinkage long fh_sys_mkdirat(struct pt_regs *regs) {
    long ret;

    check_filename("fh_sys_mkdirat", (int)regs->di, (void*)regs->si);

    ret = real_sys_mkdirat(regs);
    pr_info("mkdirat() after: %ld\n", ret);

    return ret;
}

/*
  %rax __NR_creat
  %di const char *pathname
  %si int mode
*/
static asmlinkage long fh_sys_creat(struct pt_regs *regs) {
    long ret;

    check_filename("fh_sys_creat", AT_FDCWD, (void*)regs->di);

    ret = real_sys_creat(regs);
    pr_info("creat() after: %ld\n", ret);

    return ret;
}


#else

static asmlinkage long (*real_sys_clone)(unsigned long clone_flags,
                                         unsigned long newsp,
                                         int __user *parent_tidptr,
                                         int __user *child_tidptr,
                                         unsigned long tls);

static asmlinkage long (*real_sys_execve)(
    const char __user *filename, const char __user *const __user *argv,
    const char __user *const __user *envp);

static asmlinkage long (*real_sys_execveat)(
    int fd, const char __user *filename, const char __user *const __user *argv,
    const char __user *const __user *envp, int flags);




static asmlinkage long fh_sys_clone(unsigned long clone_flags,
                                    unsigned long newsp,
                                    int __user *parent_tidptr,
                                    int __user *child_tidptr,
                                    unsigned long tls)
{
	long ret;

	pr_info("clone() before\n");

	ret = real_sys_clone(clone_flags, newsp, parent_tidptr,
                         child_tidptr, tls);

	pr_info("clone() after: %ld\n", ret);

	return ret;
}

static asmlinkage long fh_sys_execve(const char __user *filename,
                                     const char __user *const __user *argv,
                                     const char __user *const __user *envp)
{
    long ret;
    char *kernel_filename;

    kernel_filename = duplicate_filename(filename);
    pr_info("execve() before: %s\n", kernel_filename);
    kfree(kernel_filename);

    ret = real_sys_execveat(AT_FDCWD, filename, argv, envp, 0);
    pr_info("execveat() after: %ld\n", ret);

    return ret;
}

static asmlinkage long fh_sys_execveat(
    int fd,
    const char __user *filename,
    const char __user *const __user *argv,
    const char __user *const __user *envp,
    int flags)
{
    long ret;
    char *kernel_filename;

    kernel_filename = duplicate_filename(filename);
    pr_info("execveat() before: %s\n", kernel_filename);
    kfree(kernel_filename);

    ret = real_sys_execveat(fd, filename, argv, envp, flags);
    pr_info("execveat() after: %ld\n", ret);

    return ret;
}


#endif

/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook demo_hooks[] = {
	HOOK("sys_clone",  fh_sys_clone,  &real_sys_clone),
	HOOK("sys_execve", fh_sys_execve, &real_sys_execve),
    HOOK("sys_execveat", fh_sys_execveat, &real_sys_execveat),
    HOOK("sys_open", fh_sys_open, &real_sys_open),
    HOOK("sys_openat", fh_sys_openat, &real_sys_openat),
    HOOK("sys_mkdir", fh_sys_mkdir, &real_sys_mkdir),
    HOOK("sys_mkdirat", fh_sys_mkdirat, &real_sys_mkdirat),
    HOOK("sys_creat", fh_sys_creat, &real_sys_creat),
};

static int fh_init(void)
{
	int err;

	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	pr_info("module loaded\n");

	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));

	pr_info("module unloaded\n");
}
module_exit(fh_exit);
