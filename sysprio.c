#include <linux/types.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "bond_3ad.h"

#define DEBUG 1


struct agg {
	uint16_t actor_system_priority;
	uint16_t partner_system_priority;

	uint8_t actor_port_priority;
	uint8_t actor_port_number;

	uint8_t partner_port_number;
	uint8_t partner_port_priority;

	struct mac_addr aggregator_mac_address;
	struct mac_addr partner_system;
};

struct lacp_prio_params {
	uint16_t system_priority;
	struct mac_addr mac_addr;
};

static bool *__actor_better(struct agg *aggregator)
{
	if (aggregator->actor_system_priority < aggregator->partner_system_priority)
		return true;
	else if (aggregator->actor_system_priority > aggregator->partner_system_priority)
		return false;
	else if (memcmp(&aggregator->aggregator_mac_address.mac_addr_value,
			&aggregator->partner_system.mac_addr_value, ETH_ALEN) <= 0)
		return true;
	return false;
}

static void inline __fill_params(uint16_t system_priority, struct mac_addr *mac_addr, struct lacp_prio_params *params)
{
	params->system_priority = system_priority;
	memcpy(&params->mac_addr.mac_addr_value, mac_addr->mac_addr_value, sizeof(mac_addr->mac_addr_value));
}

static int __compare_lacp_prio_params(struct lacp_prio_params *param1, struct lacp_prio_params *param2)
{
	if (param1->system_priority < param2->system_priority)
		return -1;
	else if (param1->system_priority > param2->system_priority)
		return 1;

	return memcmp(param1->mac_addr.mac_addr_value, param2->mac_addr.mac_addr_value,
				sizeof(uint8_t)*ETH_ALEN);
}

static struct agg *__compare_actors(struct agg *curr, struct agg *best)
{
	if (curr->actor_port_priority > best->actor_port_priority)
		return best;
	else if (curr->actor_port_priority < best->actor_port_priority)
		return curr;
	else if (curr->actor_port_number < best->actor_port_number)
		return curr;
	return best;
}

static struct agg *__compare_partners(struct agg *curr, struct agg *best)
{
	if (curr->partner_port_priority > best->partner_port_priority)
		return best;
	else if (curr->partner_port_priority < best->partner_port_priority)
		return curr;
	else if (curr->partner_port_number < best->partner_port_number)
		return curr;
	return best;
}

static struct agg *__compare_lacp_prio(struct agg *curr, struct agg *best)
{
	struct lacp_prio_params curr_params, best_params;
	int result;
	uint16_t actor_system_priority = curr->actor_system_priority;
	bool curr_actor = __actor_better(curr);
	bool best_actor = __actor_better(best);

	if (DEBUG) {
		printf("curr: %s\n", curr_actor ? "actor" : "partner");
		printf("best: %s\n", best_actor ? "actor" : "partner");
	}

	if (curr_actor && best_actor)
		return __compare_actors(curr, best);

	if (curr_actor)
		__fill_params(actor_system_priority, &curr->aggregator_mac_address, &curr_params);
	else
		__fill_params(curr->partner_system_priority, &curr->partner_system, &curr_params);

	if (best_actor)
		__fill_params(actor_system_priority, &best->aggregator_mac_address, &best_params);
	else
		__fill_params(best->partner_system_priority, &best->partner_system, &best_params);

	result = __compare_lacp_prio_params(&curr_params, &best_params);
	if (result < 0)
		return curr;
	else if (result > 0)
		return best;

	return __compare_partners(curr, best);
}


static void printAddr(struct mac_addr *addr)
{
	for (int i = 0; i < ETH_ALEN - 1; i++)
		printf("%02x:", addr->mac_addr_value[i]);
	printf("%02x\n", addr->mac_addr_value[5]);
}

static void printAgg(struct agg *agg)
{
	printf("\tActor system id: ");
	printAddr(&agg->aggregator_mac_address);
	printf("\tActor system prio: %d\n", agg->actor_system_priority);
	printf("\tActor port prio: %d\n", agg->actor_port_priority);
	printf("\tActor port number: %d\n", agg->actor_port_number);

	printf("\tPartner system id: ");
	printAddr(&agg->partner_system);
	printf("\tPartner system prio: %d\n", agg->partner_system_priority);

}

int main(void)
{
	struct agg curr, best, *result;
	struct mac_addr addr1, addr2, addr3;

	memcpy(&addr1.mac_addr_value, (uint8_t []){ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, sizeof(addr1.mac_addr_value));
	memcpy(&addr2.mac_addr_value, (uint8_t []){ 0x02, 0x01, 0x01, 0x01, 0x01, 0x01 }, sizeof(addr1.mac_addr_value));
	memcpy(&addr3.mac_addr_value, (uint8_t []){ 0x03, 0x01, 0x01, 0x01, 0x01, 0x01 }, sizeof(addr1.mac_addr_value));

	curr.actor_system_priority = 3;
	curr.actor_port_priority = 255;
	curr.actor_port_number = 1;
	curr.aggregator_mac_address = addr1;
	curr.partner_system_priority = 1;
	curr.partner_system = addr2;

	best.actor_system_priority = 3;
	best.actor_port_priority = 255;
	best.actor_port_number = 2;
	best.aggregator_mac_address = addr1;
	best.partner_system_priority = 2;
	best.partner_system = addr3;



	/* Partner system prio compare */
	printf("\n\nPartner system priority test\n\n");



	curr.partner_system_priority = 1;	/* Should be better */
	best.partner_system_priority = 2;
	printf("\n[BEST]:\n");
	printAgg(&best);
	printf("[CURR]:\n");
	printAgg(&curr);
	printf("1.It should be curr(curr.partner_sys_prio < best.partner_sys_prio < actor_sys_prio) => curr\n");
	result = __compare_lacp_prio(&curr, &best);
	printf("\n[BETTER]: ");
	if ((struct agg *)&curr == result)
		printf("Curr (Right)\n");
	else
		printf("Best (Wrong)\n");



	curr.partner_system_priority = 4;
	best.partner_system_priority = 2;	/* Should be better */
	printf("\n[BEST]:\n");
	printAgg(&best);
	printf("[CURR]:\n");
	printAgg(&curr);
	printf("2.It should be best(best.partner_sys_prio < actor_sys_prio < best.partner_sys_prio) => best\n");
	result = __compare_lacp_prio(&curr, &best);
	printf("\n[BETTER]: ");
	if ((struct agg *)&curr == result)
		printf("Curr (Wrong)\n");
	else
		printf("Best (Right)\n");



	curr.partner_system_priority = 3;
	best.partner_system_priority = 3;
	curr.aggregator_mac_address = addr3;
	best.aggregator_mac_address = addr3;
	best.partner_system = addr2;
	curr.partner_system = addr1;
	printf("\n[BEST]:\n");
	printAgg(&best);
	printf("[CURR]:\n");
	printAgg(&curr);
	printf("3.It should be curr(actor_sys_prio = best.partner_sys_prio = best.partner_sys_prio)\n");
	printf("(curr.partner_sys_id < best.partner_sys_id < actor_sys_id) => curr\n");
	result = __compare_lacp_prio(&curr, &best);
	printf("\n[BETTER]: ");
	if ((struct agg *)&curr == result)
		printf("Curr (Right)\n");
	else
		printf("Best (Wrong)\n");



	curr.partner_system_priority = 3;
	best.partner_system_priority = 3;
	curr.aggregator_mac_address = addr3;
	best.aggregator_mac_address = addr3;
	best.partner_system = addr1;
	curr.partner_system = addr2;
	printf("\n[BEST]:\n");
	printAgg(&best);
	printf("[CURR]:\n");
	printAgg(&curr);
	printf("4.It should be best(actor_sys_prio = best.partner_sys_prio = best.partner_sys_prio)\n");
	printf("(best.partner_sys_id < curr.partner_sys_id < actor_sys_id) => best\n");
	result = __compare_lacp_prio(&curr, &best);
	printf("\n[BETTER]: ");
	if ((struct agg *)&curr == result)
		printf("Curr (Wrong)\n");
	else
		printf("Best (Right)\n");



	curr.partner_system_priority = 3;	/* Should be better (port number lower then best, mac-addr lower partners) */
	best.partner_system_priority = 3;
	curr.aggregator_mac_address = addr1;
	best.aggregator_mac_address = addr1;
	curr.partner_system = addr3;
	printf("\n[BEST]:\n");
	printAgg(&best);
	printf("[CURR]:\n");
	printAgg(&curr);
	printf("5.It should be curr(actor_sys_prio = best.partner_sys_prio = best.partner_sys_prio)\n");
	printf("(actor_sys_id < curr.partner_sys_id < best.partner_sys_id) => actor\n");
	printf("(curr.port_prio = best.port_prio)\n");
	printf("(curr.port_num < best.port_num) => curr\n");
	result = __compare_lacp_prio(&curr, &best);
	printf("\n[BETTER]: ");
	if ((struct agg *)&curr == result)
		printf("Curr (Right)\n");
	else
		printf("Best (Wrong)\n");



	curr.partner_system_priority = 3;	/* Should be better (port number lower then best, mac-addr lower partners) */
	best.partner_system_priority = 3;
	curr.aggregator_mac_address = addr1;
	best.aggregator_mac_address = addr1;
	curr.partner_system = addr3;
	curr.actor_port_priority = 1;
	best.actor_port_priority = 2;
	printf("\n[BEST]:\n");
	printAgg(&best);
	printf("[CURR]:\n");
	printAgg(&curr);
	printf("6.It should be curr(actor_sys_prio = best.partner_sys_prio = best.partner_sys_prio)\n");
	printf("(actor_sys_id < curr.partner_sys_id < best.partner_sys_id) => actor\n");
	printf("(curr.port_prio < best.port_prio) => curr\n");
	result = __compare_lacp_prio(&curr, &best);
	printf("\n[BETTER]: ");
	if ((struct agg *)&curr == result)
		printf("Curr (Right)\n");
	else
		printf("Best (Wrong)\n");



	curr.partner_system_priority = 3;	/* Should be better (port number lower then best, mac-addr lower partners) */
	best.partner_system_priority = 3;
	curr.aggregator_mac_address = addr1;
	best.aggregator_mac_address = addr1;
	curr.partner_system = addr3;
	curr.actor_port_priority = 2;
	best.actor_port_priority = 1;
	printf("\n[BEST]:\n");
	printAgg(&best);
	printf("[CURR]:\n");
	printAgg(&curr);
	printf("7.It should be best(actor_sys_prio = best.partner_sys_prio = best.partner_sys_prio)\n");
	printf("(actor_sys_id < curr.partner_sys_id < best.partner_sys_id) => actor\n");
	printf("(best.port_prio < curr.port_prio) => best\n");
	result = __compare_lacp_prio(&curr, &best);
	printf("\n[BETTER]: ");
	if ((struct agg *)&curr == result)
		printf("Curr (Wrong)\n");
	else
		printf("Best (Right)\n");



	curr.partner_system_priority = 3;
	best.partner_system_priority = 3;
	curr.aggregator_mac_address = addr3;
	best.aggregator_mac_address = addr3;
	best.partner_system = addr1;
	curr.partner_system = addr2;
	curr.partner_port_priority = 255;
	best.partner_port_priority = 255;
	curr.partner_port_number = 1;
	best.partner_port_number = 2;
	printf("\n[BEST]:\n");
	printAgg(&best);
	printf("[CURR]:\n");
	printAgg(&curr);
	printf("8.It should be best(actor_sys_prio = best.partner_sys_prio = best.partner_sys_prio)\n");
	printf("(best.partner_sys_id = curr.partner_sys_id < actor_sys_id)\n");
	printf("(curr.partner_port_prio = best.partner_port_prio)\n");
	printf("(best.partner_port_num < curr.partner_port_num) => best\n");
	result = __compare_lacp_prio(&curr, &best);
	printf("\n[BETTER]: ");
	if ((struct agg *)&curr == result)
		printf("Curr (Wrong)\n");
	else
		printf("Best (Right)\n");



	return 0;
}
