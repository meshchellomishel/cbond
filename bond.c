#include <netlink/route/link/bonding.h>
#include <netlink/route/link.h>
#include <netlink/route/link/bridge.h>
#include <netlink/netlink.h>
#include <netlink/handlers.h>
#include <netlink/cache.h>
#include <netlink/errno.h>
#include <netlink/types.h>
#include <netlink/msg.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <linux/types.h>
#include <errno.h>


#define LAG_MODE_LOADBALANCE 3
#define LAG_MODE_LACP 4
#define LAG_DEFAULT_MIIMON 100
#define BOND_TYPE "bond"

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

struct bond {
	struct nl_sock *sock;
	struct nl_cache *cache;
	struct nl_sock *evcb;
};


struct bond_req {
	struct nlmsghdr n;
	struct ifinfomsg i;
};


static struct bond *bond_alloc(void)
{
	struct bond *bond = NULL;

	bond = malloc(sizeof(struct bond));
	if (!bond)
		return NULL;

	bond->sock = NULL;
	bond->cache = NULL;

	return bond;
}

int bond_modify_cb(struct nl_msg *msg, void *arg)
{
	struct bond *bond = arg;

	printf("Callback called\n");

	return NL_SKIP;
}

static int set_socket(struct bond *bond)
{
	int ret;

	bond->sock = nl_socket_alloc();
	if (!bond->sock) {
		printf("ERROR: Failed to create a nl_socket\n");
		return -1;
	}

	bond->evcb = nl_socket_alloc();
	if (!bond->evcb) {
		printf("ERROR: Failed to create event socket\n");
		return -1;
	}

	nl_socket_set_peer_groups(bond->evcb, RTMGRP_LINK | RTMGRP_NOTIFY);
	ret = nl_cb_set(bond->evcb, NL_CB_MSG_IN, NL_CB_CUSTOM, bond_modify_cb, bond);
	if (ret < 0) {
		printf("ERROR: Failed to set callback function to socket\n");
		return ret;
	}

	ret = nl_connect(bond->evcb, NETLINK_ROUTE);
	if (ret < 0) {
		printf("ERROR: Failed to connect to event socket\n");
		return ret;
	}

	ret = nl_connect(bond->sock, NETLINK_ROUTE);
	if (ret < 0) {
		printf("ERROR: Failed to connect to nl socket\n");
		return ret;
	}

	ret = nl_socket_set_nonblocking(bond->sock);
	if (ret < 0) {
		printf("ERROR: Failed to set nl socket into non blocking\n");
		return ret;
	}

	return 0;
}


static int set_cahce(struct bond *bond)
{
	int ret;

	ret = rtnl_link_alloc_cache_flags(bond->sock, AF_UNSPEC, &bond->cache, NL_CACHE_AF_ITER);
	if (ret < 0) {
		printf("ERROR: Failed to alloc link cache\n");
		return ret;
	}

	return 0;
}

int bond_init(struct bond *bond)
{
	int ret;

	ret = set_socket(bond);
	if (ret < 0) {
		printf("ERROR: failed to set socket\n");
		return ret;
	}

	return set_cahce(bond);
}

void bond_destroy(struct bond *bond)
{
	if (bond) {
		if (bond->sock)
			nl_socket_free(bond->sock);
		if (bond->cache)
			nl_cache_free(bond->cache);
		if (bond->evcb)
			nl_socket_free(bond->evcb);
		free(bond);
	}
}

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
	      int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		fprintf(stderr,
			"addattr_l ERROR: message exceeded bound of %d\n",
			maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type)
{
	struct rtattr *nest = NLMSG_TAIL(n);

	addattr_l(n, maxlen, type, NULL, 0);
	return nest;
}

int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
	return n->nlmsg_len;
}

struct rtnl_link *build_bond_by_ifname(const char *ifname)
{
	struct rtnl_link *link = NULL;

	link = rtnl_link_bond_alloc();
	if (!link) {
		printf("ERROR: failed to allocate link\n");
		rtnl_link_put(link);
		return NULL;
	}
	rtnl_link_set_name(link, ifname);

	return link;
}

struct nl_msg *build_msg(int nlmsg_type, int flags, struct rtnl_link *link)
{
	int ret;
	int ifindex = 0;

	if (flags & NLM_F_CREATE)
		ifindex = rtnl_link_get_ifindex(link);
	struct nl_msg *msg = NULL;
	struct ifinfomsg ifi = {
		.ifi_family = AF_UNSPEC,
		.ifi_index = ifindex,
	};

	msg = nlmsg_alloc_simple(nlmsg_type, flags);
	if (!msg)
		return NULL;

	ret = nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO);
	if (ret < 0)
		return NULL;

	ret = rtnl_link_fill_info(msg, link);
	if (ret < 0)
		return NULL;

	return msg;
}

int _fill_default_info(struct nl_msg *msg, const char *ifname)
{
	int ret;
	int iflatype;
	struct rtattr *linkinfo, *data;
	char *type = BOND_TYPE;

	linkinfo = nla_nest_start(msg, IFLA_LINKINFO);
	{
		nla_put_string(msg, IFLA_INFO_KIND, type);

		data = nla_nest_start(msg, IFLA_INFO_DATA);
		{
			nla_put_u8(msg, IFLA_BOND_MODE, LAG_MODE_LOADBALANCE);
			nla_put_u32(msg, IFLA_BOND_MIIMON, LAG_DEFAULT_MIIMON);
		}
		nla_nest_end(msg, data);
	}
	nla_nest_end(msg, linkinfo);

	return 0;
}

int _enslave_iface(struct bond *bond, struct rtnl_link *slave, int master)
{
	int ret;
	struct rtnl_link *changes = NULL;
	int slave_index = rtnl_link_get_ifindex(slave);
	unsigned int flags = rtnl_link_get_flags(slave);

	changes = rtnl_link_alloc();
	if (!changes) {
		printf("ERROR: Failed to allocate change link\n");
		return -1;
	}

	if (flags & IFF_UP)
		rtnl_link_unset_flags(changes, IFF_UP);
	ret = rtnl_link_change(bond->sock, slave, changes, 0);
	if (ret < 0) {
		printf("ERROR: Failed to apply changes on iface\n");
		return ret;
	}

	printf("Enslaving %d to %d...\n", slave_index, master);
	return rtnl_link_bond_enslave_ifindex(bond->sock, master, slave_index);
}

int enslave_iface(struct bond *bond, const char *master_name, const char *slave_name)
{
	int ret;
	int master = -1;
	struct rtnl_link *slave = NULL;

	master = rtnl_link_name2i(bond->cache, master_name);
	if (master < 0) {
		printf("ERROR: Failed to get master`s link by name\n");
		return -1;
	}
	slave = rtnl_link_get_by_name(bond->cache, slave_name);
	if (!slave) {
		printf("ERROR: Failed to get slave`s link by name\n");
		return -1;
	}

	ret = _enslave_iface(bond, slave, master);
	if (ret < 0)
		printf("ERROR: Failed to enslave iface\n");

	rtnl_link_put(slave);
	return ret;
}

int nl_talk(struct bond *bond, struct nl_msg *msg)
{
	int ret;

	ret = nl_send_auto(bond->sock, msg);
	if (ret < 0) {
		printf("ERROR: Failed to send msg(%s)\n", nl_geterror(ret));
		return ret;
	}

	ret = nl_recvmsgs_default(bond->sock);
	if (ret < 0) {
		printf("Failed to recv NL mesgs: %s\n", nl_geterror(ret));
		return ret;
	}

	return 0;
}

int create_bond(struct bond *bond, const char *ifname)
{
	int ret;
	struct nl_msg *msg;
	struct rtnl_link *link = NULL;

	link = build_bond_by_ifname(ifname);
	if (!link) {
		printf("ERROR: Failed to create bond iface\n");
		return -1;
	}
	msg = build_msg(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE, link);
	if (!msg) {
		printf("ERROR: Failed to create msg\n");
		return -1;
	}
	ret = _fill_default_info(msg, link);
	if (ret < 0) {
		printf("ERROR: Failed to fill default info\n");
		return ret;
	}
	ret = nl_talk(bond, msg);

	rtnl_link_put(link);
	return ret;
}

int delete_bond(struct bond *bond, const char *ifname)
{
	int ret;
	struct nl_msg *msg = NULL;
	struct rtnl_link *link = NULL;

	link = rtnl_link_get_by_name(bond->cache, ifname);
	if (!link) {
		printf("ERROR: Failed to found iface\n");
		return 0;
	}
	msg = build_msg(RTM_DELLINK, 0, link);
	ret = nl_talk(bond, msg);

	rtnl_link_put(link);
	return ret;
}

void parse_attrs(unsigned char *buf)
{
	int ret;
	struct nlmsghdr *h = buf;
	struct nlattr *tb[IFLA_MAX + 1], *linkinfo[IFLA_INFO_MAX + 1], *bond[IFLA_BOND_MAX + 1];

	ret = nlmsg_parse(h, sizeof(struct ifinfomsg), &tb, IFLA_MAX, NULL);
	if (ret < 0) {
		printf("Failed to parse args\n");
		return;
	}

	if (!tb[IFLA_LINKINFO]) {
		printf("no linkinfo\n");
		return;
	}

	ret = nla_parse_nested(&linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO], NULL);
	if (ret < 0) {
		printf("Failed to parse linkinfo\n");
		return;
	}

	if (linkinfo[IFLA_INFO_SLAVE_KIND]) {
		printf("type: %s_slave\n", nla_get_string(linkinfo[IFLA_INFO_SLAVE_KIND]));
		if (linkinfo[IFLA_INFO_SLAVE_DATA]) {
			ret = nla_parse_nested(&bond, IFLA_BOND_MAX, linkinfo[IFLA_INFO_SLAVE_DATA], NULL);
			if (ret < 0) {
				printf("Failed to parse linkinfo\n");
				return;
			}

			printf("GOODe %d\n", nla_get_u16(bond[IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE]));
		} else
			printf("NO INFO slave\n");
	}

	if (linkinfo[IFLA_INFO_KIND]) {
		if (linkinfo[IFLA_INFO_DATA]) {
			ret = nla_parse_nested(&bond, IFLA_BOND_MAX, linkinfo[IFLA_INFO_DATA], NULL);
			if (ret < 0) {
				printf("Failed to parse linkinfo\n");
				return;
			}

			printf("GOOD %d\n", nla_get_u16(bond[IFLA_BOND_AD_ACTOR_SYS_PRIO]));
		} else
			printf("NO INFO bond\n");
	}
}

int main(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (fd < 0) {
		printf("Ошибка создания netlink сокета: %s", strerror(errno));
		return 1;
	}

	struct sockaddr_nl local;
	char buf[8192];
	struct iovec iov;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK | RTMGRP_NOTIFY;
	local.nl_pid = getpid();

	struct msghdr msg;
	{
		msg.msg_name = &local;
		msg.msg_namelen = sizeof(local);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
	}

	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		printf("Ошибка связывания с netlink сокетом: %s", (char *)strerror(errno));
		close(fd);
		return 1;
	}

	// читаем и разбираем сообщения из сокета
	while (1) {
		ssize_t status = recvmsg(fd, &msg, MSG_DONTWAIT);

		if (status < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				usleep(250000);
				continue;
			}

			printf("Ошибка приема сообщения netlink: %s", (char *)strerror(errno));
			continue;
		}

		parse_attrs(&buf);
	}
on_error:
	return 0;
}
