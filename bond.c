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
#include <event2/event.h>


#define LAG_MODE_LOADBALANCE 3
#define LAG_MODE_LACP 4
#define LAG_DEFAULT_MIIMON 100
#define BOND_TYPE "bond"

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))


struct cache_mngr {
	struct event *event;
	struct nl_sock *sk;
	struct nl_cache_mngr *nl_mngr;
	int *cache_err;
};
struct bond {
	struct nl_sock *sock;
	struct nl_cache *cache;
	struct nl_sock *evcb;

	struct cache_mngr *mngr;

	struct event_base *evbase;
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

	bond->mngr = NULL;
	bond->mngr = malloc(sizeof(struct cache_mngr));
	if (!bond->mngr)
		return NULL;

	return bond;
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

	ret = nl_socket_set_nonblocking(bond->evcb);
	if (ret < 0) {
		printf("ERROR: Failed to set nl socket into non blocking\n");
		return ret;
	}

	return 0;
}


static void cache_change_cb(struct nl_cache *cache, struct nl_object *o_obj,
			    struct nl_object *n_obj, uint64_t attr_diff,
			    int nl_act, void *data)
{
	int ret;
	struct bond *bond = data;
	struct nl_msg *msg = NULL;

	msg = nlmsg_alloc();
	if (!msg) {
		printf("ERROR: Failed to allocate message\n");
		goto exit;
	}

	ret = recvmsg(bond->sock, msg, MSG_DONTWAIT);
	if (ret < 0) {
		printf("ERROR: Failed to recv message from nl_sock(%s)\n", strerror(-ret));
		goto exit;
	}

exit:
	nlmsg_free(msg);
}

static void cache_mngr_event_handler(int fd, short flags, void *data)
{
	struct cache_mngr *mngr = data;
	int ret;

	ret = nl_cache_mngr_data_ready(mngr->nl_mngr);
	if (ret < 0) {
		printf("Failed to process NL messages: %s\n",
		     nl_geterror(ret));
		*mngr->cache_err = ret;
	}
}

static int set_cahce(struct bond *bond)
{
	int ret;
	struct cache_mngr *mngr = bond->mngr;

	mngr->sk = nl_socket_alloc();
	if (!mngr->sk) {
		printf("ERROR: Failed to allocate manager socket\n");
		return -1;
	}

	ret = nl_cache_mngr_alloc(mngr->sk, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr->nl_mngr);
	if (ret < 0) {
		printf("ERROR: Failed to allocate cache manager(%s)\n", nl_geterror(ret));
		return ret;
	}

	ret = rtnl_link_alloc_cache_flags(mngr->sk, AF_UNSPEC, &bond->cache, NL_CACHE_AF_ITER);
	if (ret < 0) {
		printf("ERROR: Failed to alloc link cache\n");
		return ret;
	}

	ret = nl_cache_mngr_add_cache_v2(mngr->nl_mngr, bond->cache,
					 cache_change_cb, bond);
	if (ret < 0) {
		printf("Failed to add 'route/link' cache to manager: %s\n",
		     nl_geterror(ret));
		nl_cache_free(bond->cache);
		return ret;
	}

	mngr->event = event_new(bond->evbase, nl_cache_mngr_get_fd(mngr->nl_mngr),
		EV_READ | EV_PERSIST, cache_mngr_event_handler,
		mngr);
	if (!mngr->event) {
		printf("Failed to create mngr netlink event\n");
		return -1;
	}

	ret = event_add(mngr->event, NULL);
	if (ret < 0) {
		printf("Failed to add netlink event\n");
		return -1;
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

	bond->evbase = event_base_new();
	if (!bond->evbase) {
		printf("ERROR: Failed to allocate new evbase\n");
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

		// free(bond);
	}
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
			nla_put_u8(msg, IFLA_BOND_MODE, LAG_MODE_LACP);
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

int main(void)
{
	int ret;
	struct bond *bond = NULL;

	const char *ifname = "bond1";
	const char *slave = "enp29s0";

	bond = bond_alloc();
	bond_init(bond);

	ret = create_bond(bond, ifname);
	if (ret < 0)
		printf("ERROR: Failed to create bonding iface '%s'\n", ifname);

	ret = enslave_iface(bond, ifname, slave);
	if (ret < 0) {
		printf("ERROR: Failed to enslave iface: %s\n", nl_geterror(ret));
		goto on_error;
	}
	// delete_bond(bond, ifname);
	while (1) {
		ret = event_base_loop(bond->evbase, EVLOOP_ONCE);
		if (ret < 0) {
			printf("Event loop failed\n");
			goto on_error;
		}
	}
on_error:
	// bond_destroy(bond);
	return 0;
}
