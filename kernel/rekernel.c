// SPDX-License-Identifier: GPL-2.0
/*
 * Re:Kernel integration helpers
 */

#include <linux/freezer.h>
#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/proc_fs.h>
#include <linux/rekernel.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>

static struct sock *rekernel_netlink;
static int netlink_unit = NETLINK_REKERNEL_MIN;
static struct proc_dir_entry *rekernel_dir, *rekernel_unit_entry;

bool line_is_frozen(struct task_struct *task)
{
    return frozen(task->group_leader) || freezing(task->group_leader);
}

int send_netlink_message(char *msg, u16 len)
{
    struct sk_buff *skbuffer;
    struct nlmsghdr *nlhdr;

    skbuffer = nlmsg_new(len, GFP_ATOMIC);
    if (!skbuffer)
        return -ENOMEM;

    nlhdr = nlmsg_put(skbuffer, 0, 0, netlink_unit, len, 0);
    if (!nlhdr) {
        nlmsg_free(skbuffer);
        return -ENOMEM;
    }

    memcpy(nlmsg_data(nlhdr), msg, len);
    return netlink_unicast(rekernel_netlink, skbuffer, USER_PORT,
                            MSG_DONTWAIT);
}

static void netlink_rcv_msg(struct sk_buff *skbuffer)
{
    /* Ignoring received messages */
}

static struct netlink_kernel_cfg rekernel_cfg = {
    .input = netlink_rcv_msg,
};

static int rekernel_unit_show(struct seq_file *m, void *v)
{
    seq_printf(m, "%d\n", netlink_unit);
    return 0;
}

static int rekernel_unit_open(struct inode *inode, struct file *file)
{
    return single_open(file, rekernel_unit_show, NULL);
}

static const struct file_operations rekernel_unit_fops = {
    .open           = rekernel_unit_open,
    .read           = seq_read,
    .llseek         = seq_lseek,
    .release        = single_release,
    .owner          = THIS_MODULE,
};

int start_rekernel_server(void)
{
    char buff[32];

    if (rekernel_netlink)
        return 0;

    for (netlink_unit = NETLINK_REKERNEL_MIN;
         netlink_unit < NETLINK_REKERNEL_MAX; netlink_unit++) {
        rekernel_netlink = (struct sock *)netlink_kernel_create(&init_net,
                                         netlink_unit, &rekernel_cfg);
        if (rekernel_netlink)
            break;
    }

    if (!rekernel_netlink)
        return -EINVAL;

    rekernel_dir = proc_mkdir("rekernel", NULL);
    if (rekernel_dir) {
        sprintf(buff, "%d", netlink_unit);
        rekernel_unit_entry = proc_create(buff, 0644, rekernel_dir,
                                       &rekernel_unit_fops);
        if (!rekernel_unit_entry)
            pr_info("create rekernel unit failed!\n");
    } else {
        pr_info("create /proc/rekernel failed!\n");
    }

    pr_info("Created Re:Kernel server! NETLINK UNIT: %d\n", netlink_unit);
    return 0;
}
EXPORT_SYMBOL(start_rekernel_server);
EXPORT_SYMBOL(send_netlink_message);
EXPORT_SYMBOL(line_is_frozen);
