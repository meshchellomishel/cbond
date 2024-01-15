#include <netlink/route/link/bonding.h>
#include <netlink/route/link.h>
#include <netlink/route/link/bridge.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/errno.h>
#include <netlink/types.h>
#include <netlink/msg.h>
#include <linux/if_link.h>


#define LAG_MODE_LOADBALANCE 3
#define LAG_MODE_LACP 4
#define BOND_TYPE "bond"

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

struct bond {
	struct nl_sock *sock;
	struct nl_cache *cache;
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

static int set_socket(struct bond *bond)
{
	int ret;

	bond->sock = nl_socket_alloc();
	if (!bond->sock) {
		printf("ERROR: Failed create a nl_socket\n");
		return -1;
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

	ret = set_cahce(bond);

	return ret;
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

struct rtnl_link *build_link_by_ifname(const char *ifname)
{
	struct rtnl_link *link = NULL;

	link = rtnl_link_bond_alloc();
	if (!link) {
		printf("ERROR: failed to allocate link\n");
		return NULL;
	}
	rtnl_link_set_name(link, ifname);

	return link;
}

struct nl_msg *build_msg(int nlmsg_type, int flags, struct rtnl_link *link)
{
	int ret;
	struct nl_msg *msg = NULL;
	struct ifinfomsg ifi = {
		.ifi_family = AF_UNSPEC,
		.ifi_index = rtnl_link_get_ifindex(link),
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
		}
		nla_nest_end(msg, data);
	}
	nla_nest_end(msg, linkinfo);

	return 0;
}


int sendNL(struct bond *bond, struct nl_msg *msg)
{
	int status;

	status = nl_send_auto(bond->sock, msg);
	if (status < 0) {
		perror("Cannot talk to rtnetlink");
		return -1;
	}
}

int fill_default(struct nl_msg *msg)
{
	// int ret;

	// ret = _fill_default_info(msg);
	// if (ret < 0) {
	// 	printf("ERROR: failed to fill default info\n");
	// 	return ret;
	// }

	return 0;
}


int main(void)
{
	int ret;
	struct bond *bond = NULL;
	struct nl_msg *msg;
	struct rtnl_link *link = NULL;
	const char *ifname = "bond1";

	bond = bond_alloc();
	bond_init(bond);

	link = build_link_by_ifname(ifname);
	printf("%d\n", rtnl_link_get_ifindex(link));
	msg = build_msg(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL, link);
	_fill_default_info(msg, link);
	sendNL(bond, msg);

	ret = nl_recvmsgs_default(bond->sock);
	if (ret != 0) {
		printf("Failed to recv NL mesgs: %s", nl_geterror(ret));
		return -1;
	}

	return 0;
}
