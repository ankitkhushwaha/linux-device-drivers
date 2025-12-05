#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/kconfig.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define OURMODNAME "dbgfs_simple_intf"

MODULE_AUTHOR("Ankit");
MODULE_DESCRIPTION("U<->K interfacing via debugfs");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

static int cause_an_oops;
module_param(cause_an_oops, int, 0644);
MODULE_PARM_DESC(cause_an_oops,
                 "Setting this to 1 can cause a kernel bug, an Oops; if 1, we do NOT perform"
                 " required cleanup! so, after removal, any op on the debugfs files will cause"
                 " an Oops! (default is 0, no bug)");

static struct dentry *gparent;

DEFINE_MUTEX(mtx);

struct drv_ctx
{
    int tx, rx, err, myword, power;
    u32 config1;
    u32 config2;
    u64 config3; /* updated to the 'jiffies' value ... */
#define MAXBYTES 128
    char oursecret[MAXBYTES];
};
static struct drv_ctx *gdrvctx;
static int debug_level; /* 'off' (0) by default ... */

static ssize_t dbgfs_debug_level_read(struct file *filp,
                                      char __user *ubuf, size_t count, loff_t *fpos)
{
    char locbuf[MAXBYTES];
    int *debug_val = (int *)filp->f_inode->i_private;

    pr_info("trying to read %zu bytes\n", count);
    if (mutex_lock_interruptible(&mtx))
    {
        return -ERESTARTSYS;
    }
    snprintf(locbuf, MAXBYTES, "%d", *debug_val);
    mutex_unlock(&mtx);

return simple_read_from_buffer(ubuf, MAXBYTES, fpos, locbuf, sizeof(locbuf));
}

static ssize_t dbgfs_debug_level_write(struct file *filp, const char __user *ubuf, size_t count, loff_t *fpos)
{
    int debug_val = debug_level, ret = count;
    char kbuf[MAXBYTES];
    
    loff_t *pos = fpos;
    if (mutex_lock_interruptible(&mtx))
    {
        return -ERESTARTSYS;
    }
    pr_info("trying to write %zu bytes\n", count);
    if (count == 0 || count >= 12)
    {
        return -EINVAL;
    }
    if (*pos > MAXBYTES)
    {
        return 0;
    }
    if (count + *pos > MAXBYTES)
    {
        count = MAXBYTES - *pos;
    }
    ret = copy_from_user(kbuf, ubuf, count);
    if (ret)
    {
        pr_warn("failed to copy from user space\n");
        goto out;
    }
    ret = kstrtoint(kbuf, 0, &debug_val);
    if (ret)
    {
        pr_warn("failed to convert kbuf to int\n");
        goto out;
    }
    pr_info("new debug_value: %d\n", debug_val);
    if (debug_val < 0 || debug_val > 2)
    {
        ret = -EINVAL;
        pr_warn("invalid debug value: %d, valid range-[0-2]\n", debug_val);
        goto out;
    }
    debug_level = debug_val;
    ret = count;
out:
    mutex_unlock(&mtx);
    return ret;
}

static const struct file_operations dbgfs_debug_level_fops = {
    .read = dbgfs_debug_level_read,
    .write = dbgfs_debug_level_write,
};

static ssize_t dbgfs_show_drvctx(struct file *filp, char __user *ubuf,
                                 size_t count, loff_t *fpos)
{
    struct drv_ctx *data = (struct drv_ctx *)filp->f_inode->i_private;

#define MAXUPASS 256
    char locbuf[MAXUPASS];

    if (mutex_lock_interruptible(&mtx))
    {
        return -ERESTARTSYS;
    }
    data->config3 = jiffies;
    snprintf(locbuf, MAXUPASS - 1,
             "prodname:%s\n"
             "tx:%d,rx:%d,err:%d,myword:%d,power:%d\n"
             "config1:0x%x,config2:0x%x,config3:0x%llx,\n"
             "oursecret:%s\n",
             OURMODNAME,
             data->tx, data->rx, data->err, data->myword, data->power,
             data->config1, data->config2, data->config3,
             data->oursecret);
    mutex_unlock(&mtx);
    return simple_read_from_buffer(ubuf, MAXUPASS, fpos, locbuf, sizeof(locbuf));
}

static const struct file_operations dbgfs_drvctx_fops = {
    .read = dbgfs_show_drvctx,
};

static struct drv_ctx *alloc_init_drvctx(void)
{
    struct drv_ctx *drvctx = NULL;

    drvctx = kzalloc(sizeof(struct drv_ctx), GFP_KERNEL);
    if (!drvctx)
    {
        return ERR_PTR(-ENOMEM);
    }
    drvctx->config1 = 0x0;
    drvctx->config2 = 0x48524a5f;
    drvctx->config3 = jiffies;
    drvctx->power = 1;
    strncpy(drvctx->oursecret, "AhA yyy", 8);

    pr_info("allocated and init the driver context structure\n");
    return drvctx;
}

static int __init debugfs_simple_intf_init(void)
{
    int stat = 0;
    debug_level = 0;
    struct dentry *file1, *file2;

    if (!IS_ENABLED(CONFIG_DEBUG_FS))
    {
        pr_warn("debugfs unsupported! Aborting ...\n");
        return -ENODEV;
    }

    gparent = debugfs_create_dir(OURMODNAME, NULL);
    if (!gparent)
    {
        pr_info("debugfs_create_dir failed, aborting...\n");
        stat = PTR_ERR(gparent);
        goto out_fail_1;
    }

    gdrvctx = alloc_init_drvctx();
    if (IS_ERR(gdrvctx))
    {
        pr_info("drv ctx alloc failed, aborting...\n");
        stat = PTR_ERR(gdrvctx);
        goto out_fail_2;
    }
#define DBGFS_FILE1 "llkd_dbgfs_show_drvctx"
    file1 = debugfs_create_file(DBGFS_FILE1, 0440, gparent,
                                (void *)gdrvctx, &dbgfs_drvctx_fops);
    if (!file1)
    {
        pr_info("debugfs_create_file failed, aborting...\n");
        stat = PTR_ERR(file1);
        goto out_fail_3;
    }
#define DBGFS_FILE2 "llkd_dbgfs_debug_level"
    file2 = debugfs_create_file(DBGFS_FILE2, 0644, gparent, (void *)&debug_level, &dbgfs_debug_level_fops);
    // debugfs_create_u32(DBGFS_FILE2, 0644, gparent, &debug_level);

    pr_debug("debugfs file 2 <debugfs_mountpt>/%s/%s created\n", OURMODNAME, DBGFS_FILE2);

    pr_info("initialized (fyi, our 'cause an Oops' setting is currently %s)\n",
            cause_an_oops == 1 ? "On" : "Off");
    return 0;

out_fail_3:
    kfree(gdrvctx);
out_fail_2:
    debugfs_remove_recursive(gparent);
out_fail_1:
    return stat;
}

static void __exit debugfs_simple_intf_cleanup(void)
{
    kfree(gdrvctx);
    if (!cause_an_oops)
        debugfs_remove_recursive(gparent);
    pr_info("removed\n");
}

module_init(debugfs_simple_intf_init);
module_exit(debugfs_simple_intf_cleanup);
