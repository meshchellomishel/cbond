/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 1999 - 2004 Intel Corporation. All rights reserved.
 */


/* General definitions */
#define PKT_TYPE_LACPDU         cpu_to_be16(ETH_P_SLOW)
#define AD_TIMER_INTERVAL       100 /*msec*/

#define AD_LACP_SLOW 0
#define AD_LACP_FAST 1

#define ETH_ALEN 6

typedef struct mac_addr {
	uint8_t mac_addr_value[ETH_ALEN];
};

enum {
	BOND_AD_STABLE = 0,
	BOND_AD_BANDWIDTH = 1,
	BOND_AD_COUNT = 2,
};

struct slave;
struct bonding;
struct ad_info;
struct port;

/* aggregator structure(43.4.5 in the 802.3ad standard) */
typedef struct aggregator {
	struct mac_addr aggregator_mac_address;
	uint16_t aggregator_identifier;
	bool is_individual;
	uint16_t actor_admin_aggregator_key;
	uint16_t actor_oper_aggregator_key;
	struct mac_addr partner_system;
	uint16_t partner_system_priority;
	uint16_t partner_oper_aggregator_key;
	uint16_t receive_state;	/* BOOLEAN */
	uint16_t transmit_state;	/* BOOLEAN */
	struct port *lag_ports;
	/* ****** PRIVATE PARAMETERS ****** */
	struct slave *slave;	/* pointer to the bond slave that this aggregator belongs to */
	uint16_t is_active;		/* BOOLEAN. Indicates if this aggregator is active */
	uint16_t num_of_ports;
} aggregator_t;

struct port_params {
	struct mac_addr system;
	uint16_t system_priority;
	uint16_t key;
	uint16_t port_number;
	uint16_t port_priority;
	uint16_t port_state;
};

/* port structure(43.4.6 in the 802.3ad standard) */
typedef struct port {
	uint16_t actor_port_number;
	uint16_t actor_port_priority;
	struct mac_addr actor_system;	/* This parameter is added here although it is not specified in the standard, just for simplification */
	uint16_t actor_system_priority;	/* This parameter is added here although it is not specified in the standard, just for simplification */
	uint16_t actor_port_aggregator_identifier;
	bool ntt;
	uint16_t actor_admin_port_key;
	uint16_t actor_oper_port_key;
	uint8_t actor_admin_port_state;
	uint8_t actor_oper_port_state;

	struct port_params partner_admin;
	struct port_params partner_oper;

	bool is_enabled;

	/* ****** PRIVATE PARAMETERS ****** */
	uint16_t sm_vars;		/* all state machines variables for this port */
	uint16_t sm_rx_timer_counter;	/* state machine rx timer counter */
	uint16_t sm_periodic_timer_counter;	/* state machine periodic timer counter */
	uint16_t sm_mux_timer_counter;	/* state machine mux timer counter */
	uint16_t sm_tx_timer_counter;	/* state machine tx timer counter(allways on - enter to transmit state 3 time per second) */
	uint16_t sm_churn_actor_timer_counter;
	uint16_t sm_churn_partner_timer_counter;
	uint32_t churn_actor_count;
	uint32_t churn_partner_count;
	struct slave *slave;		/* pointer to the bond slave that this port belongs to */
	struct aggregator *aggregator;	/* pointer to an aggregator that this port related to */
	struct port *next_port_in_aggregator;	/* Next port on the linked list of the parent aggregator */
	uint32_t transaction_id;		/* continuous number for identification of Marker PDU's; */
} port_t;

/* system structure */
struct ad_system {
	uint16_t sys_priority;
	struct mac_addr sys_mac_addr;
};


/* ========== AD Exported structures to the main bonding code ========== */
#define BOND_AD_INFO(bond)   ((bond)->ad_info)
#define SLAVE_AD_INFO(slave) ((slave)->ad_info)

struct ad_bond_info {
	struct ad_system system;	/* 802.3ad system structure */
	uint16_t aggregator_identifier;
};

struct ad_slave_info {
	struct aggregator aggregator;	/* 802.3ad aggregator structure */
	struct port port;		/* 802.3ad port structure */
	uint16_t id;
};
