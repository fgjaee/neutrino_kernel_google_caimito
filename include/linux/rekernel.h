/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Re:Kernel integration helpers
 */

#ifndef _LINUX_REKERNEL_H
#define _LINUX_REKERNEL_H

#include <linux/sched.h>

#define NETLINK_REKERNEL_MAX                    26
#define NETLINK_REKERNEL_MIN                    22
#define USER_PORT                               100
#define PACKET_SIZE                             128
#define MIN_USERAPP_UID                         (10000)
#define MAX_SYSTEM_UID                          (2000)
#define RESERVE_ORDER                           17
#define WARN_AHEAD_SPACE                        (1 << RESERVE_ORDER)

int start_rekernel_server(void);
int send_netlink_message(char *msg, u16 len);
bool line_is_frozen(struct task_struct *task);

#endif /* _LINUX_REKERNEL_H */
