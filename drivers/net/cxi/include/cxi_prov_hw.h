/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Copyright 2020,2024 Hewlett Packard Enterprise Development LP */
#ifndef __CXI_PROV_HW_H__
#define __CXI_PROV_HW_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct cxi_md;
struct cxi_cq;
struct cxi_eq;
struct cxi_cp;

/* CXI hardware provider interface */

/* Memory descriptor structure */
struct cxi_md {
    uint64_t iova;          /* I/O virtual address */
    uint32_t lac;           /* Local Access Control */
    uint32_t len;           /* Length of memory region */
    void *va;               /* Virtual address */
    uint32_t flags;         /* Memory flags */
};

/* Command queue structure */
struct cxi_cq {
    uint32_t cq_id;         /* Command queue ID */
    void *cq_base;          /* Command queue base address */
    uint32_t cq_size;       /* Command queue size */
    struct cxi_md *md;      /* Memory descriptor for CQ */
};

/* Event queue structure */
struct cxi_eq {
    uint32_t eq_id;         /* Event queue ID */
    void *eq_base;          /* Event queue base address */
    uint32_t eq_size;       /* Event queue size */
    struct cxi_md *md;      /* Memory descriptor for EQ */
};

/* Communication profile structure */
struct cxi_cp {
    uint32_t cp_id;         /* Communication profile ID */
    uint32_t vni;           /* Virtual Network ID */
    uint32_t tc;            /* Traffic class */
};

/* CQ allocation options */
struct cxi_cq_alloc_opts {
    uint32_t count;         /* Number of entries */
    uint32_t flags;         /* Allocation flags */
    bool is_tx;             /* TX or target CQ */
};

/* EQ attributes */
struct cxi_eq_attr {
    uint32_t count;         /* Number of entries */
    uint32_t flags;         /* EQ flags */
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

/**
 * cxi_cq_ring() - Ring the command queue doorbell
 * @cq: Command queue
 *
 * This function rings the doorbell to notify hardware of new commands.
 */
void cxi_cq_ring(struct cxi_cq *cq);

/**
 * cxi_eq_get_event() - Get event from event queue
 * @eq: Event queue
 * @event: Pointer to store event
 *
 * Return: 0 on success, negative error code on failure
 */
int cxi_eq_get_event(struct cxi_eq *eq, void *event);

/**
 * cxi_eq_ack_events() - Acknowledge processed events
 * @eq: Event queue
 * @count: Number of events to acknowledge
 */
void cxi_eq_ack_events(struct cxi_eq *eq, uint32_t count);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __CXI_PROV_HW_H__ */
