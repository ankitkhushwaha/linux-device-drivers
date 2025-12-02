#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/compiler.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <linux/pid_types.h>

#define MAXBYTES 128

int open_tsk_display(struct inode *, struct file *);
ssize_t read_tsk_display(struct file *, char __user *, size_t, loff_t *);
ssize_t write_tsk_display(struct file *, const char __user *, size_t, loff_t *);

struct tsk_display
{
    struct device *dev;
    pid_t tsk_pid;
};

static const struct file_operations tsk_display_fops = {
    .open = open_tsk_display,
    .read = read_tsk_display,
    .write = write_tsk_display,
};

static struct tsk_display *tskd;

int open_tsk_display(struct inode *inode, struct file *filp)
{
    char *buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (unlikely(!buf))
        return -ENOMEM;
    pr_info("opening '%s' now; wrt open file: f_flags = 0x%x\n",
            file_path(filp, buf, PATH_MAX), filp->f_flags);

    kfree(buf);

    return nonseekable_open(inode, filp);
}

ssize_t read_tsk_display(struct file *filp,
                         char __user *ubuf,
                         size_t count, loff_t *off)
{
    int ret = count;
    pid_t tpid_t = tskd->tsk_pid;
    struct pid *pid = NULL;
    struct device *dev = tskd->dev;
    struct task_struct *task = NULL;

    dev_info(dev, "reading tsk info for pid: %d", tpid_t);

    pid = find_get_pid(tpid_t);
    if (!pid)
    {
        dev_warn(dev, "Invalid pid: %d", tpid_t);
        goto out_nomem;
    }
    if (pid_has_task(pid, PIDTYPE_PID))
    {
        task = get_pid_task(pid, PIDTYPE_PID);
        if (IS_ERR(task))
        {
            ret = PTR_ERR(task);
            goto out_mem;
        }
    }

    printk(KERN_INFO "PID: %d, TGID: %d, Comm: %s\n, recent_used_cpu:%d on_rq:%d", 
        task->pid, task->tgid, task->comm, task->recent_used_cpu, task->on_rq);
    return 0;
out_nomem:
    return ret;
}

ssize_t write_tsk_display(struct file *filp,
                          const char __user *ubuf,
                          size_t count, loff_t *off)
{
    int ret = count;
    int tpid = 0;
    void *kbuf = NULL;
    struct device *dev = tskd->dev;

    if (unlikely(count > MAXBYTES))
    {
        dev_warn(dev, "execeeds write bytes limit");
        goto out_nomem;
    }

    kbuf = kvmalloc(count, GFP_KERNEL);
    if (unlikely(!kbuf))
        goto out_nomem;
    memset(kbuf, 0, count);

    if (copy_from_user(kbuf, ubuf, count))
    {
        ret = -EFAULT;
        dev_warn(dev, "copy_from_user failed\n");
        goto out_cfu;
    }
    dev_info(dev, "kbuf: %s", (char *)kbuf);

    ret = kstrtoint(kbuf, 0, &tpid);
    if (ret)
    {
        dev_warn(dev, "failed to convert kbuf to uint");
    }

    tskd->tsk_pid = tpid;
    dev_info(dev, "pid: %d written to /dev/task_display", tpid);
    ret = count;
out_cfu:
    kvfree(kbuf);
out_nomem:
    return ret;
}

static struct miscdevice tsk_display_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "task_display",
    .mode = 0666,
    .fops = &tsk_display_fops,
};

static int __init task_display_init(void)
{
    int ret;
    struct device *dev;

    ret = misc_register(&tsk_display_dev);
    if (ret)
    {
        pr_notice("task display device registration failed, aborting\n");
        return ret;
    }
    dev = tsk_display_dev.this_device;

    tskd = devm_kzalloc(dev, sizeof(struct tsk_display), GFP_KERNEL);

    if (unlikely(!tskd))
        return -ENOMEM;

    tskd->dev = dev;
    tskd->tsk_pid = 0;

    return 0;
}

static void __exit task_display_exit(void)
{
    misc_deregister(&tsk_display_dev);
    pr_info("task display driver deregistered, bye\n");
    return;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ankit");
MODULE_DESCRIPTION("task-display-device");

module_init(task_display_init);
module_exit(task_display_exit);