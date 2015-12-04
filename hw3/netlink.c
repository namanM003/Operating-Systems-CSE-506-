#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "netlink.h"
#define NETLINK_USER 31

#define MAX_PAYLOAD 1024 /* maximum payload size*/
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;
/* We will need to pass the same argument object to createsocket and
 * listen_to_kernel because as per me kernel will be filling the data in the
 * same object and for displaying we will need the object also we will need to
 * find a method to stop the pthread after getting the message. (IFF we use
 * pthread.
 */
int createSocket(int pid)
{
	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);

	if (sock_fd < 0) {
		return -1;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = pid; /* self pid */
	bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

	memset(&dest_addr, 0, sizeof(dest_addr));
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;

	dest_addr.nl_pid = 0; /* For Linux Kernel */
	dest_addr.nl_groups = 0; /* unicast */

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = pid;
	nlh->nlmsg_flags = 0;


	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return 1;
}

void listen_to_kernel() {
	char * data;
	printf("Listening to kernel\n");
	recvmsg(sock_fd, &msg, 0);
	printf("Received Message\n");
	data = (char *)NLMSG_DATA(nlh);
	printf(" %s\n", data);
	close(sock_fd);
	pthread_exit(0);
	
}
