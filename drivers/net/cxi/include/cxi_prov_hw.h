// SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
/*
 * Copyright 2018-2020 Cray Inc. All rights reserved
 *
 * CXI event queue and command queue definitions and accessors.
 */

#ifndef __CXI_PROV_HW
#define __CXI_PROV_HW

#ifndef __KERNEL__
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * wp_fence() - Fence operation used before advancing the command queue write
 * pointer. This ensures that all commands are write visible before hardware
 * processing the write pointer update.
 *
 * wc_fence() - Fence operation used to ensuring ordering between writes to
 * write combining buffers.
 */

#if defined(__aarch64__)

#define aarch64_dmb(opt) asm volatile ("dmb " #opt ::: "memory")

#define sfence() aarch64_dmb(oshst)

/* Data memory barrier with outer shareability is enough to ensure write
 * ordering between host memory command writes and write pointer doorbell
 * writes.
 */
#define wp_fence() aarch64_dmb(oshst)

/* Data memory barrier with outer shareability is enough writes to device memory
 * gather regions (i.e. write combined regions) are ordered with respect to
 * subsequent device memory gather region writes.
 */
#define wc_fence() aarch64_dmb(oshst)

#elif defined(__x86_64__)

#define sfence() __asm__ __volatile__  ( "sfence" ::: "memory" )
#define wp_fence() sfence()
#define wc_fence() sfence()

#else
#error "Unsupported architecture"
#endif

/* Forward declarations */
struct cxi_md;
struct cxi_cq;
struct cxi_eq;
struct cxi_cp;
struct cxi_lni;
struct cxi_dev;
struct cxi_wait_obj;

/* Command structures from official header */
struct cxi_cmd32 {
    uint8_t pad[32];
};

#define C_CQ_CMD_SIZE 64
#define C_CQ_FIRST_WR_PTR 4
#define C_CQ_FIRST_WR_PTR_32 (2 * C_CQ_FIRST_WR_PTR)

#define LL_OFFSET(wp32) ((((wp32) / 2) & 0x0f) * 64)

struct cxi_cmd64 {
    uint8_t pad[C_CQ_CMD_SIZE];
};

#define C_EE_CFG_ECB_SIZE 64

/* Event union from official header */
union c_event {
    /* Use as event header, to access event_size and event_type only */
    struct c_event_cmd_fail hdr;

    struct c_event_initiator_short	init_short;
    struct c_event_initiator_long	init_long;
    struct c_event_trig_op_short	trig_short;
    struct c_event_trig_op_long	trig_long;
    struct c_event_cmd_fail		cmd_fail;
    struct c_event_target_long	tgt_long;
    struct c_event_target_short	tgt_short;
    struct c_event_target_enet	enet;
    struct c_event_enet_fgfc	enet_fgfc;
    struct c_event_timestamp	timestamp;
    struct c_event_eq_switch	eq_switch;
    struct c_event_pct          pct;
};

/* CXI hardware provider interface */

/* Memory descriptor structure */
struct cxi_md {
    uint64_t iova;          /* I/O virtual address */
    uint32_t lac;           /* Local Access Control */
    uint32_t len;           /* Length of memory region */
    void *va;               /* Virtual address */
    uint32_t flags;         /* Memory flags */
    void *md;               /* libcxi memory descriptor handle */
    bool is_mapped;         /* Mapping status */
};

/* User command queue - from official cxi_prov_hw.h */
struct cxi_cq {
    /* Command queue size */
    unsigned int size;

    /* Memory mapped write pointer location */
    uint64_t *wp_addr;

    /* Low-latency write regions. */
    uint8_t *ll_64;
    uint8_t *ll_128a;
    uint8_t *ll_128u;

    /* CQ status and commands buffer. CQ status occupies the first 8 32-byte
     * slots. Commands start after.
     */
    union {
        struct cxi_cmd32 *cmds32;
        volatile struct c_cq_status *status;
    };
    uint64_t rp32;

    /* CQ index. Transmit CQs use 0 to 1023, and target CQs use
     * 1024 to 1535. Use cxi_cq_get_cqn() to retrieve the CQ
     * number, going from 0 to 1023, or 0 to 512 respectively. */
    unsigned int idx;

    /* 32-bytes internal write pointer */
    unsigned int size32;
    uint64_t wp32;
    uint64_t hw_wp32;
};

/* User event queue - from official cxi_prov_hw.h */
struct cxi_eq {
    /* Event queue byte size */
    unsigned int byte_size;

    /* EQ software state, which includes the read pointer. Keep a
     * local copy and update the fields as needed before copying
     * it to the adapter. */
    union c_ee_cfg_eq_sw_state sw_state;
    uint64_t *sw_state_addr;

    /* Cached status write-back timestamp. */
    uint64_t last_ts_sec;
    uint64_t last_ts_ns;

    /* Current read offset */
    unsigned int rd_offset;

    /* Previous read offset - before last call to
     * cxi_eq_ack_events() */
    unsigned int prev_rd_offset;

    /* The allocated EQ number, which will be used in commands. */
    unsigned int eqn;

    /* Backpointer for the owner of the EQ. */
    void *context;

    union {
        /* Ring buffer for events */
        uint8_t *events;

        /* EQ status write-back pointer. Updated when the number of free
         * events crosses a configurable threshold, or when events are
         * dropped. */
        struct c_eq_status *status;
    };
};

/* Communication profile structure */
struct cxi_cp {
    uint32_t cp_id;         /* Communication profile ID */
    uint32_t vni;           /* Virtual Network ID */
    uint32_t tc;            /* Traffic class */
    uint32_t lcid;          /* Local Communication ID */
};

/* CQ allocation options */
struct cxi_cq_alloc_opts {
    uint32_t count;         /* Number of entries */
    uint32_t flags;         /* Allocation flags */
    bool is_tx;             /* TX or target CQ */
    uint32_t policy;        /* CQ update policy */
    uint32_t lcid;          /* Local Communication ID */
};

/* EQ attributes */
struct cxi_eq_attr {
    uint32_t count;         /* Number of entries */
    uint32_t flags;         /* EQ flags */
    void *queue;            /* Queue buffer */
    size_t queue_len;       /* Queue buffer length */
};

/* MD hints */
struct cxi_md_hints {
    uint32_t flags;         /* Hint flags */
};

/* Service descriptor */
struct cxi_svc_desc {
    uint32_t svc_id;        /* Service ID */
    char name[32];          /* Service name */
    uint32_t resource_limits; /* Resource limits */
};

/* Resource usage */
struct cxi_rsrc_use {
    uint32_t resource_type; /* Resource type */
    uint32_t in_use;        /* Currently in use */
    uint32_t reserved;      /* Reserved count */
};

/* Traffic class types */
enum cxi_traffic_class_type {
    CXI_TC_TYPE_DEFAULT = 0,
    CXI_TC_TYPE_LOW_LATENCY = 1,
    CXI_TC_TYPE_BULK_DATA = 2,
    CXI_TC_TYPE_DEDICATED = 3,
};

/* Traffic classes */
enum cxi_traffic_class {
    CXI_TC_DEDICATED_ACCESS = 0,
    CXI_TC_LOW_LATENCY = 1,
    CXI_TC_BULK_DATA = 2,
    CXI_TC_BEST_EFFORT = 3,
};

/* Cassini versions */
enum cassini_version {
    CASSINI_1_0 = 0,
    CASSINI_1_1 = 1,
    CASSINI_2_0 = 2,
};

/* System type identifiers */
enum system_type_identifier {
    SYSTEM_TYPE_UNKNOWN = 0,
    SYSTEM_TYPE_HOMOGENEOUS = 1,
    SYSTEM_TYPE_MIXED = 2,
};

/* CXI constants - only define if not already defined */
#ifndef CXI_MAX_CQ_COUNT
#define CXI_MAX_CQ_COUNT        1024
#endif
#ifndef CXI_MAX_CQS
#define CXI_MAX_CQS             1024
#endif
#ifndef CXI_MAX_EQS
#define CXI_MAX_EQS             2048
#endif
#ifndef CXI_CQ_SIZE_MIN
#define CXI_CQ_SIZE_MIN         64
#endif
#ifndef CXI_CQ_SIZE_MAX
#define CXI_CQ_SIZE_MAX         65536
#endif
#ifndef CXI_EQ_SIZE_MIN
#define CXI_EQ_SIZE_MIN         64
#endif
#ifndef CXI_EQ_SIZE_MAX
#define CXI_EQ_SIZE_MAX         65536
#endif

/* CQ flags */
#define CXI_CQ_IS_TX            (1 << 0)
#define CXI_CQ_TX_ETHERNET      (1 << 1)

/* CQ update policies */
#define CXI_CQ_UPDATE_LOW_FREQ_EMPTY    0

/* Memory mapping flags */
#define CXI_MAP_PIN             (1 << 0)
#define CXI_MAP_READ            (1 << 1)
#define CXI_MAP_WRITE           (1 << 2)

/* Memory alignment */
#define CXI_MD_ALIGN            4096

/* Additional structures needed by the driver */
struct cxi_eth_caps {
    uint32_t max_mtu;
    uint32_t min_mtu;
    bool supports_checksum;
    bool supports_tso;
    bool supports_rss;
    bool supports_vlan;
    uint32_t max_queues;
};

struct cxi_link_info {
    uint32_t speed;
    uint32_t state;
    uint32_t mtu;
    uint32_t duplex;
    uint32_t autoneg;
    uint32_t link_status;
};

struct c_cstate_cmd {
    uint32_t opcode;
    uint32_t flags;
    uint32_t restricted;
    uint32_t event_success_disable;
    uint32_t eq;
};

/* CXI hardware interface functions */

/**
 * cxi_cq_emit_dma_eth() - Emit DMA ethernet command
 * @cq: Command queue
 * @cmd: DMA ethernet command structure
 *
 * Return: 0 on success, negative error code on failure
 */
int cxi_cq_emit_dma_eth(struct cxi_cq *cq, const struct c_dma_eth_cmd *cmd);

/**
 * cxi_cq_emit_idc_eth() - Emit IDC ethernet command
 * @cq: Command queue
 * @cmd: IDC ethernet command structure
 * @data: Data buffer
 * @len: Data length
 *
 * Return: 0 on success, negative error code on failure
 */
int cxi_cq_emit_idc_eth(struct cxi_cq *cq, const struct c_idc_eth_cmd *cmd,
                        const void *data, uint8_t len);

/* cxi_cq_ring is defined as inline function below */

/**
 * cxi_eq_ack_events() - Acknowledge processed events
 * @eq: Event queue
 * @count: Number of events to acknowledge
 */
void cxi_eq_ack_events(struct cxi_eq *eq, uint32_t count);

/* Essential inline functions from official cxi_prov_hw.h */

/* Check to see if command queue is empty. */
static inline bool cxi_cq_empty(struct cxi_cq *cq)
{
    uint64_t wp = cq->wp32 / 2;
    return wp == cq->status->rd_ptr;
}

/* Check if event queue is empty */
static inline bool cxi_eq_empty(struct cxi_eq *eq)
{
    unsigned int rd_offset = eq->rd_offset;
    const union c_event *event = (union c_event *)(eq->events + rd_offset);

    if (event->hdr.event_size == C_EVENT_SIZE_NO_EVENT)
        return true;
    return false;
}

/* Get the next event on an event queue without advancing the read pointer */
static inline const union c_event *cxi_eq_peek_event(struct cxi_eq *eq)
{
    if (cxi_eq_empty(eq))
        return NULL;

    unsigned int rd_offset = eq->rd_offset;
    const union c_event *event = (const union c_event *)(eq->events + rd_offset);
    return event;
}

/* Get the next event on an event queue */
static inline const union c_event *cxi_eq_get_event(struct cxi_eq *eq)
{
    const union c_event *event = cxi_eq_peek_event(eq);
    if (!event)
        return NULL;

    /* Advance to next event would go here */
    return event;
}

/* Ring a command queue doorbell */
static inline void cxi_cq_ring(struct cxi_cq *cq)
{
    /* Write the write pointer to the doorbell */
    if (cq->wp_addr) {
        wp_fence();
        *cq->wp_addr = cq->wp32 / 2;
    }
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __CXI_PROV_HW_H__ */
