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


int _fill_default_info(struct nl_msg *msg)
{
	const char *bond_type = BOND_TYPE;
	struct nlattr *tb[IFLA_MAX + 1] = {};

	tb[IFLA_LINKINFO] = nla_nest_start(msg, IFLA_LINKINFO);
	if (!tb[IFLA_LINKINFO]) {
		printf("ERROR: failed to start nested args\n");
		return -1;
	}

	nla_put_string(msg, IFLA_INFO_KIND, bond_type);
	// nla_put_u8(msg, IFLA_BOND_MODE, LAG_MODE_LOADBALANCE);
	nla_nest_end(msg, tb[IFLA_LINKINFO]);

	return 0;
}


int fill_default(struct nl_msg *msg)
{
	int ret;

	ret = _fill_default_info(msg);
	if (ret < 0) {
		printf("ERROR: failed to fill default info\n");
		return ret;
	}

	return 0;
}


int main(void)
{
	int ret;
	char *bond_name = "bond1";
	struct nl_msg *msg = NULL;
	struct bond *bond = NULL;

	bond = bond_alloc();
	if (!bond) {
		printf("ERROR: failed to alloc bond structure\n");
		return -1;
	}

	ret = bond_init(bond);
	if (ret < 0) {
		printf("ERROR: failed to init bond\n");
		free(bond);
		goto bond_free;
	}

	// struct rtnl_link *link = rtnl_link_bond_add(bond->sock, bond_name, link);

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);
	if (!msg) {
		printf("ERROR: failed to alloc message\n");
		goto bond_free;
	}

	ret = fill_default(msg);
	if (ret < 0) {
		printf("ERROR: failed to fill default info\n");
		goto msg_free;
	}
	// ret = rtnl_link_fill_info(msg, link);
	// if (ret < 0) {
	// 	printf("ERROR: failed to fill info\n");
	// 	return -1;
	// }

	ret = nl_send_sync(bond->sock, msg);
	if (ret < 0) {
		printf("ERROR: failed to send msg\n");
		goto msg_free;
	}

msg_free:
	nlmsg_free(msg);
bond_free:
	free(bond);

	return 0;
}
