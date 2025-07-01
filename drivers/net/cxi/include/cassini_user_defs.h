// SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
/*
 * Cassini hardware definitions
 * Copyright 2018-2021 Hewlett Packard Enterprise Development LP
 *
 * This file is generated. Do not modify.
 */
#ifndef __CASSINI_USER_DEFS_H
#define __CASSINI_USER_DEFS_H

#include <stdint.h>

#ifndef __LITTLE_ENDIAN
#error "Non-little endian builds not supported"
#endif

#ifndef __KERNEL__
#include <endian.h>
#define be64_to_cpu be64toh
#define be32_to_cpu be32toh
#define be16_to_cpu be16toh
#define cpu_to_be64 htobe64
#define cpu_to_be32 htobe32
#define cpu_to_be16 htobe16
#endif

/* Hardware constants */
#define C_NUM_CTS 2048
#define C_CT_NONE 0
#define C_AC_NONE 0
#define C_CID_NONE 0
#define C_NUM_EQS 2048
#define C_EQ_NONE 0
#define C_NUM_ACS 1024
#define C_NUM_PTLTES 2048
#define C_NUM_TRANSMIT_CQS 1024
#define C_NUM_TARGET_CQS 512
#define C_NID_ANY 1048575

/* Ethernet specific constants */
#define C_MAX_ETH_FRAGS 5
#define C_MAX_IDC_PAYLOAD_RES 224
#define C_MAX_IDC_PAYLOAD_UNR 192

/* Command types */
enum c_cmd_type {
    C_CMD_TYPE_IDC = 0,
    C_CMD_TYPE_DMA = 1,
    C_CMD_TYPE_CT = 2,
    C_CMD_TYPE_CQ = 3,
};

/* DMA operations */
enum c_dma_op {
    C_CMD_NOOP = 0,
    C_CMD_PUT = 1,
    C_CMD_GET = 2,
    C_CMD_RENDEZVOUS_PUT = 3,
    C_CMD_ATOMIC = 4,
    C_CMD_FETCHING_ATOMIC = 5,
    C_CMD_ETHERNET_TX = 6,
    C_CMD_SMALL_MESSAGE = 7,
    C_CMD_NOMATCH_PUT = 8,
    C_CMD_NOMATCH_GET = 9,
    C_CMD_CSTATE = 10,
    C_CMD_CLOSE = 11,
    C_CMD_CLEAR = 12,
    C_CMD_REDUCTION = 13,
};

/* Event types */
enum c_event_type {
    C_EVENT_PUT = 0,
    C_EVENT_GET = 1,
    C_EVENT_ATOMIC = 2,
    C_EVENT_FETCH_ATOMIC = 3,
    C_EVENT_PUT_OVERFLOW = 4,
    C_EVENT_GET_OVERFLOW = 5,
    C_EVENT_ATOMIC_OVERFLOW = 6,
    C_EVENT_FETCH_ATOMIC_OVERFLOW = 7,
    C_EVENT_SEND = 8,
    C_EVENT_ACK = 9,
    C_EVENT_REPLY = 10,
    C_EVENT_LINK = 11,
    C_EVENT_SEARCH = 12,
    C_EVENT_STATE_CHANGE = 13,
    C_EVENT_UNLINK = 14,
    C_EVENT_RENDEZVOUS = 15,
    C_EVENT_ETHERNET = 16,
    C_EVENT_COMMAND_FAILURE = 17,
    C_EVENT_TRIGGERED_OP = 18,
    C_EVENT_ETHERNET_FGFC = 19,
    C_EVENT_PCT = 20,
    C_EVENT_MATCH = 21,
    C_EVENT_ERROR = 28,
    C_EVENT_TIMESTAMP = 29,
    C_EVENT_EQ_SWITCH = 30,
    C_EVENT_NULL_EVENT = 31,
};

/* Return codes */
enum c_return_code {
    C_RC_NO_EVENT = 0,
    C_RC_OK = 1,
    C_RC_UNDELIVERABLE = 2,
    C_RC_PT_DISABLED = 3,
    C_RC_DROPPED = 4,
    C_RC_PERM_VIOLATION = 5,
    C_RC_OP_VIOLATION = 6,
    C_RC_NO_MATCH = 8,
    C_RC_UNCOR = 9,
    C_RC_UNCOR_TRNSNT = 10,
    C_RC_NO_SPACE = 16,
    C_RC_ENTRY_NOT_FOUND = 18,
    C_RC_NO_TARGET_CONN = 19,
    C_RC_NO_TARGET_MST = 20,
    C_RC_NO_TARGET_TRS = 21,
    C_RC_SEQUENCE_ERROR = 22,
    C_RC_NO_MATCHING_CONN = 23,
    C_RC_INVALID_DFA_FORMAT = 24,
    C_RC_VNI_NOT_FOUND = 25,
    C_RC_PTLTE_NOT_FOUND = 26,
    C_RC_PTLTE_SW_MANAGED = 27,
    C_RC_SRC_ERROR = 28,
    C_RC_MST_CANCELLED = 29,
    C_RC_HRP_CONFIG_ERROR = 30,
    C_RC_HRP_RSP_ERROR = 31,
    C_RC_HRP_RSP_DISCARD = 32,
    C_RC_INVALID_AC = 33,
    C_RC_PAGE_PERM_ERROR = 34,
    C_RC_ATS_ERROR = 35,
    C_RC_NO_TRANSLATION = 36,
    C_RC_PAGE_REQ_ERROR = 37,
    C_RC_PCIE_ERROR_POISONED = 38,
    C_RC_PCIE_UNSUCCESS_CMPL = 39,
    C_RC_AMO_INVAL_OP_ERROR = 40,
    C_RC_AMO_ALIGN_ERROR = 41,
    C_RC_AMO_FP_INVALID = 42,
    C_RC_AMO_FP_UNDERFLOW = 43,
    C_RC_AMO_FP_OVERFLOW = 44,
    C_RC_AMO_FP_INEXACT = 45,
    C_RC_ILLEGAL_OP = 46,
    C_RC_INVALID_ENDPOINT = 47,
    C_RC_RESTRICTED_UNICAST = 48,
    C_RC_CMD_ALIGN_ERROR = 49,
    C_RC_CMD_INVALID_ARG = 50,
    C_RC_INVALID_EVENT = 51,
    C_RC_ADDR_OUT_OF_RANGE = 52,
    C_RC_CONN_CLOSED = 53,
    C_RC_CANCELED = 54,
    C_RC_NO_MATCHING_TRS = 55,
    C_RC_NO_MATCHING_MST = 56,
    C_RC_DELAYED = 57,
    C_RC_AMO_LENGTH_ERROR = 58,
    C_RC_PKTBUF_ERROR = 59,
    C_RC_RESOURCE_BUSY = 60,
    C_RC_FLUSH_TRANSLATION = 61,
    C_RC_TRS_PEND_RSP = 62,
};

/* RSS hash types */
enum c_rss_hash_type {
    C_RSS_HASH_NONE = 0,
    C_RSS_HASH_IPV4 = 1,
    C_RSS_HASH_IPV4_TCP = 2,
    C_RSS_HASH_IPV4_UDP = 3,
    C_RSS_HASH_IPV4_PROTOCOL = 4,
    C_RSS_HASH_IPV4_PROTOCOL_TCP = 5,
    C_RSS_HASH_IPV4_PROTOCOL_UDP = 6,
    C_RSS_HASH_IPV4_PROTOCOL_UDP_ROCE = 7,
    C_RSS_HASH_IPV4_FLOW_LABEL = 8,
    C_RSS_HASH_IPV6 = 9,
    C_RSS_HASH_IPV6_TCP = 10,
    C_RSS_HASH_IPV6_UDP = 11,
    C_RSS_HASH_IPV6_PROTOCOL = 12,
    C_RSS_HASH_IPV6_PROTOCOL_TCP = 13,
    C_RSS_HASH_IPV6_PROTOCOL_UDP = 14,
    C_RSS_HASH_IPV6_PROTOCOL_UDP_ROCE = 15,
    C_RSS_HASH_IPV6_FLOW_LABEL = 16,
};

/* Checksum control */
enum c_checksum_ctrl {
    C_CHECKSUM_CTRL_NONE = 0,
    C_CHECKSUM_CTRL_ROCE = 1,
    C_CHECKSUM_CTRL_UDP = 2,
    C_CHECKSUM_CTRL_TCP = 3,
};

/* Command structures */
struct c_cmd {
    uint8_t cmd_type : 2;
    uint8_t cmd_size : 2;
    uint8_t opcode : 4;
};

/* IDC Ethernet command */
struct c_idc_eth_cmd {
    struct c_cmd command;
    uint8_t length;
    uint8_t flow_hash;
    uint8_t checksum_ctrl : 2;
    uint8_t : 2;
    uint8_t fmt : 1;
    uint8_t : 3;
    uint16_t checksum_start : 10;
    uint8_t : 2;
    uint16_t checksum_offset : 6;
    uint16_t : 14;
    uint64_t unused_0;
    uint8_t data[0];
} __attribute__((packed));

/* DMA Ethernet command */
struct c_dma_eth_cmd {
    struct c_cmd command;
    uint8_t read_lac : 3;
    uint8_t : 4;
    uint8_t fmt : 1;
    uint8_t flow_hash;
    uint8_t checksum_ctrl : 2;
    uint8_t : 3;
    uint8_t num_segments : 3;
    uint16_t checksum_start : 10;
    uint8_t : 2;
    uint16_t checksum_offset : 6;
    uint16_t : 14;
    uint64_t user_ptr;
    uint16_t len[7];
    uint16_t unused_0;
    uint64_t addr[7];
    uint16_t total_len;
    uint8_t event_send_disable : 1;
    uint8_t event_success_disable : 1;
    uint8_t event_ct_send : 1;
    uint8_t event_ct_reply : 1;
    uint8_t event_ct_ack : 1;
    uint8_t event_ct_bytes : 1;
    uint8_t get_with_local_flag : 1;
    uint8_t restricted : 1;
    uint8_t reduction : 1;
    uint8_t flush : 1;
    uint8_t use_offset_for_get : 1;
    uint8_t : 1;
    uint8_t : 1;
    uint8_t : 3;
    uint16_t ct : 11;
    uint8_t : 5;
    uint16_t eq : 11;
    uint8_t : 5;
} __attribute__((packed));

#endif /* __CASSINI_USER_DEFS_H */
