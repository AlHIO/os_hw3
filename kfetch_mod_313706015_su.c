#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/irq.h>
#include <asm/uaccess.h>
#include <asm/irq.h>
#include <asm/io.h>
#include <linux/poll.h>
#include <linux/cdev.h>
#include <linux/utsname.h>
#include <linux/cpumask.h> /* for num_online_cpus */
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/jiffies.h> /* for jiffies */
#include <linux/cpu.h>     // for cpu_data, cpuinfo_x86

/*
 *  Prototypes - this would normally go in a .h file
 */
int init_module(void);
void cleanup_module(void);
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

#define SUCCESS 0
#define DEVICE_NAME "kfetch" /* Dev name as it appears in /proc/devices */
#define BUF_LEN 80                         /* Max length of the message from the device */

static int Major;
static int Device_Open = 0; /* Is device open? Used to prevent multiple access to device */
static char final_output[500];
static char hostname[40];
static char kernel[40];
static char CPU_name[40];
static char CPU_core[40];
static char Mem[40];
static char process_num[40];
static char uptime_ptr[40];
static char *msg_Ptr;

char bird_lines[8][40] = {
    "                   ",
    "        .-.        ",
    "       (.. |       ",
    "       <>  |       ",
    "      / --- \\      ",
    "     ( |   | )     ",
    "   |\\_)__(_//|    ",
    "  <__)------(__>   "
};

static struct class *cls;

static struct file_operations chardev_fops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release
};

int init_module(void)
{
    Major = register_chrdev(0, DEVICE_NAME, &chardev_fops);
    if (Major < 0) {
        pr_alert("Registering char device failed with %d\n", Major);
        return Major;
    }
    pr_info("Character device registered with major number %d.\n", Major);

    cls = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(cls)) {
        pr_alert("Failed to create device class\n");
        unregister_chrdev(Major, DEVICE_NAME);
        return PTR_ERR(cls);
    }
    pr_info("Device class created successfully.\n");

    if (device_create(cls, NULL, MKDEV(Major, 0), NULL, DEVICE_NAME) == NULL) {
        pr_alert("Failed to create device node\n");
        class_destroy(cls);
        unregister_chrdev(Major, DEVICE_NAME);
        return -1;
    }
    pr_info("Device node created at /dev/%s\n", DEVICE_NAME);

    return SUCCESS;
}

void cleanup_module(void)
{
    device_destroy(cls, MKDEV(Major, 0));
    class_destroy(cls);
    unregister_chrdev(Major, DEVICE_NAME);
}

static int device_open(struct inode *inode, struct file *file)
{
    if (Device_Open)
        return -EBUSY;

    msg_Ptr = final_output;
    Device_Open++;
    try_module_get(THIS_MODULE);
    return SUCCESS;
}

static int device_release(struct inode *inode, struct file *file)
{
    Device_Open--;
    module_put(THIS_MODULE);
    return SUCCESS;
}

static ssize_t device_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    int bytes_read = 0;
    if (*msg_Ptr == 0)
        return 0;

    while (length && *msg_Ptr) {
        put_user(*(msg_Ptr++), buffer++);
        length--;
        bytes_read++;
    }
    return bytes_read;
}

static ssize_t device_write(struct file *filp, const char __user *buff, size_t len, loff_t *off)
{
    struct cpuinfo_x86 *c = &cpu_data(0);
    struct sysinfo si;
    unsigned long free_ram = 0, total_ram = 0, uptime = 0;
    int mask_info;

    si_meminfo(&si);
    free_ram = si.freeram * PAGE_SIZE / 1024 / 1024;
    total_ram = si.totalram * PAGE_SIZE / 1024 / 1024;
    uptime = jiffies_to_msecs(jiffies) / 1000;

    if (copy_from_user(&mask_info, buff, sizeof(mask_info))) {
        pr_alert("Failed to copy data from user\n");
        return -EFAULT;
    }

    sprintf(CPU_name, "%s\n", c->x86_model_id);
    sprintf(process_num, "Procs:   %d\n", num_online_cpus());
    sprintf(uptime_ptr, "Uptime:  %lu min\n", uptime / 60);
    sprintf(Mem, "Mem:     %lu MB/%lu MB\n", free_ram, total_ram);
    sprintf(kernel, "Kernel:  %s\n", utsname()->release);
    sprintf(CPU_core, "CPUS     %d/%d\n", num_online_cpus(), num_active_cpus());

    sprintf(hostname, "%s\n", utsname()->nodename);
    char dash[strlen(hostname)];
    memset(dash, '-', strlen(hostname));
    dash[strlen(hostname)] = '\0';
    sprintf(final_output, "%s%s%s%s\n", bird_lines[0], hostname, bird_lines[1], dash);

    int bitarr[6] = {0};
    for (int i = 0; i < 6; i++) {
        if (mask_info & (1 << i))
            bitarr[i] = 1;
    }

    for (int i = 0; i < 6; i++) {
        if (bitarr[i]) {
            sprintf(final_output + strlen(final_output), "%s%s", bird_lines[i + 2],
                    (i == 0) ? kernel :
                    (i == 1) ? CPU_core :
                    (i == 2) ? CPU_name :
                    (i == 3) ? Mem :
                    (i == 4) ? uptime_ptr : process_num);
        }
    }

    msg_Ptr = final_output;
    return len;
}

MODULE_LICENSE("GPL");
