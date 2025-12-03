#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/platform_device.h>

MODULE_AUTHOR("Ankit");
MODULE_DESCRIPTION("simple sysfs interface");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

#define SYSFS_FILE1 llkdsysfs_debug_level
#define SYSFS_FILE2 llkdsysfs_pgoff
#define SYSFS_FILE3 llkdsysfs_pressure

static DEFINE_MUTEX(mtx);

static int debug_level;
static u32 gpressure;

static ssize_t llkdsysfs_pressure_show(struct device *dev,
                                       struct device_attribute *attr, char *buf)
{
    int ret;

    if (mutex_lock_interruptible(&mtx))
    {
        return -ERESTARTSYS;
    }
    pr_debug("In the 'show' method: pressure=%u\n", gpressure);
    ret = snprintf(buf, 25, "%u", gpressure);
    mutex_unlock(&mtx);
    return ret;
}

DEVICE_ATTR_RO(SYSFS_FILE3);

static ssize_t llkdsysfs_pgoff_show(struct device *dev,
                                    struct device_attribute *attr, char *buf)
{
    int ret;

    if (mutex_lock_interruptible(&mtx))
    {
        return -ERESTARTSYS;
    }
    pr_debug("In the 'show' method: PAGE_OFFSET=0x%px\n", (void *)PAGE_OFFSET);
    ret = snprintf(buf, 25, "0x%px", (void *)PAGE_OFFSET);
    mutex_unlock(&mtx);
    return ret;
}

DEVICE_ATTR_RO(SYSFS_FILE2);

#define DEBUG_LEVEL_MIN 0
#define DEBUG_LEVEL_MAX 2
#define DEBUG_LEVEL_DEFAULT DEBUG_LEVEL_MIN

static ssize_t llkdsysfs_debug_level_show(struct device *dev,
                                          struct device_attribute *attr, char *buf)
{
    int ret;

    if (mutex_lock_interruptible(&mtx))
    {
        return -ERESTARTSYS;
    }
    pr_debug("In the 'show' method: DEBUG_LEVEL=%d\n", debug_level);
    ret = snprintf(buf, 25, "%d", debug_level);
    mutex_unlock(&mtx);
    return ret;
}

static ssize_t llkdsysfs_debug_level_store(struct device *dev,
                                           struct device_attribute *attr,
                                           const char *buf, size_t count)
{
    int ret = (int)count, prev_dbglevel;

    if (mutex_lock_interruptible(&mtx))
    {
        return -ERESTARTSYS;
    }
    prev_dbglevel = debug_level;
    pr_debug("In the 'store' method:\ncount=%zu, buf=0x%px, count=%zu\n "
             "Buffer content: \"%.*s\"\n",
             count, buf, count, (int)count, buf);

    if (count == 0 || count > 12)
    {
        ret = -EINVAL;
        goto out;
    }

    ret = kstrtoint(buf, 0, &debug_level);
    if (ret)
        goto out;

    if (debug_level < DEBUG_LEVEL_MIN || debug_level > DEBUG_LEVEL_MAX)
    {
        pr_info("trying to set invalid value (%d) for debug_level\n"
                " [allowed range: %d-%d]; resetting to previous (%d)\n",
                debug_level, DEBUG_LEVEL_MIN, DEBUG_LEVEL_MAX, prev_dbglevel);
        debug_level = prev_dbglevel;
        ret = -EINVAL;
        goto out;
    }

    ret = count;
out:
    mutex_unlock(&mtx);
    return ret;
}

DEVICE_ATTR_RW(SYSFS_FILE1);

static struct platform_device *sysfs_platdev;

static int __init sysfs_simple_intf_init(void)
{
    int stat = 0;
    if (unlikely(!IS_ENABLED(CONFIG_SYSFS)))
    {
        pr_warn("sysfs unsupported! Aborting.....\n");
        return -EINVAL;
    }

#define PLAT_NAME "llkd_sysfs_simple_intf_device"
    sysfs_platdev = platform_device_register_simple(PLAT_NAME, -1, NULL, 0);
    if (IS_ERR(sysfs_platdev))
    {
        stat = PTR_ERR(sysfs_platdev);
        pr_info("error (%d) registering our platform device, aborting\n", stat);
        goto out1;
    }

    stat = device_create_file(&sysfs_platdev->dev, &dev_attr_SYSFS_FILE1);
    if (stat)
    {
        pr_info("device_create_file [1] failed (%d), aborting now\n", stat);
        goto out2;
    }
    pr_debug("sysfs file [1](/sys/devices/platform/%s/%s) created\n", PLAT_NAME, __stringify(SYSFS_FILE1));

    stat = device_create_file(&sysfs_platdev->dev, &dev_attr_SYSFS_FILE2);
    if (stat)
    {
        pr_info("device_create_file [2] failed (%d), aborting now\n", stat);
        goto out3;
    }
    pr_debug("sysfs file [2](/sys/devices/platform/%s/%s) created\n", PLAT_NAME, __stringify(SYSFS_FILE2));

    stat = device_create_file(&sysfs_platdev->dev, &dev_attr_SYSFS_FILE3);
    if (stat)
    {
        pr_info("device_create_file [3] failed (%d), aborting now\n", stat);
        goto out4;
    }
    pr_debug("sysfs file [3](/sys/devices/platform/%s/%s) created\n", PLAT_NAME, __stringify(SYSFS_FILE3));

    pr_info("initialized\n");
    return 0;

out4:
    device_remove_file(&sysfs_platdev->dev, &dev_attr_SYSFS_FILE2);
out3:
    device_remove_file(&sysfs_platdev->dev, &dev_attr_SYSFS_FILE1);
out2:
    platform_device_unregister(sysfs_platdev);
out1:
    return stat;
}

static void __exit sysfs_simple_intf_cleanup(void)
{
    device_remove_file(&sysfs_platdev->dev, &dev_attr_SYSFS_FILE1);
    device_remove_file(&sysfs_platdev->dev, &dev_attr_SYSFS_FILE2);
    device_remove_file(&sysfs_platdev->dev, &dev_attr_SYSFS_FILE3);

    platform_device_unregister(sysfs_platdev);

    pr_info("removed\n");
}
module_init(sysfs_simple_intf_init);
module_exit(sysfs_simple_intf_cleanup);
