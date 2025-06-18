/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Hewlett Packard Enterprise Development LP
 */

#ifndef _CXI_HW_H_
#define _CXI_HW_H_

#include <stdint.h>
#include <stdbool.h>
#include <rte_mbuf.h>

#include "cxi_ethdev.h"

/* CXI PCI Device IDs */
#define CXI_VENDOR_ID           0x17DB  /* HPE Vendor ID */
#define CXI_DEVICE_ID_C1        0x0501  /* Cassini 1 */
#define CXI_DEVICE_ID_C2        0x0502  /* Cassini 2 */

/* Note: PMD should not access hardware registers directly.
 * All hardware access should go through libcxi API.
 * Only doorbell access is allowed for performance-critical paths.
 */

/* Command queue configuration */
#define CXI_CQ_SIZE_MIN         64
#define CXI_CQ_SIZE_MAX         4096
#define CXI_CQ_SIZE_DEFAULT     1024

/* Event queue configuration */
#define CXI_EQ_SIZE_MIN         64
#define CXI_EQ_SIZE_MAX         4096
#define CXI_EQ_SIZE_DEFAULT     1024

/* Memory descriptor limits */
#define CXI_MD_MAX_SIZE         (1ULL << 32)  /* 4GB max */
#define CXI_MD_ALIGN            4096          /* Page alignment */

/* Packet format definitions */
#define CXI_PKT_FORMAT_STD      C_PKT_FORMAT_STD
#define CXI_PKT_FORMAT_SMALL    0  /* For small packets */

/* Checksum control definitions */
#define CXI_CSUM_NONE           C_CHECKSUM_CTRL_NONE
#define CXI_CSUM_TCP            C_CHECKSUM_CTRL_TCP
#define CXI_CSUM_UDP            C_CHECKSUM_CTRL_UDP

/* Hardware capabilities - matches libcxi struct cxi_eth_caps */
struct cxi_hw_caps {
    uint32_t max_mtu;           /* Maximum MTU */
    uint32_t min_mtu;           /* Minimum MTU */
    bool supports_checksum;     /* Hardware checksum support */
    bool supports_tso;          /* TCP segmentation offload */
    bool supports_rss;          /* Receive side scaling */
    bool supports_vlan;         /* VLAN support */
    uint32_t max_queues;        /* Maximum queues */
};

/* Link information - matches libcxi struct cxi_link_info */
struct cxi_hw_link_info {
    uint32_t speed;             /* Link speed in Mbps */
    uint8_t duplex;             /* 0 = half, 1 = full */
    uint8_t autoneg;            /* 0 = off, 1 = on */
    uint8_t link_status;        /* 0 = down, 1 = up */
};

/* Hardware statistics structure */
struct cxi_hw_stats {
    uint64_t rx_packets;        /* Total RX packets */
    uint64_t rx_bytes;          /* Total RX bytes */
    uint64_t rx_errors;         /* Total RX errors */
    uint64_t rx_dropped;        /* Total RX dropped */
    uint64_t tx_packets;        /* Total TX packets */
    uint64_t tx_bytes;          /* Total TX bytes */
    uint64_t tx_errors;         /* Total TX errors */
    uint64_t tx_dropped;        /* Total TX dropped */
};

/* Hardware statistics */
struct cxi_hw_stats {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t rx_errors;
    uint64_t rx_dropped;
    uint64_t rx_crc_errors;
    uint64_t rx_length_errors;
    uint64_t rx_fifo_errors;
    
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_errors;
    uint64_t tx_dropped;
    uint64_t tx_fifo_errors;
    uint64_t tx_carrier_errors;
};

/* Function prototypes */

/* Hardware initialization and cleanup - uses libcxi */
int cxi_hw_probe(struct rte_pci_device *pci_dev);
int cxi_hw_init_device(struct cxi_adapter *adapter);
void cxi_hw_cleanup_device(struct cxi_adapter *adapter);
int cxi_hw_reset_device(struct cxi_adapter *adapter);

/* Hardware capabilities - uses libcxi */
int cxi_hw_get_capabilities(struct cxi_adapter *adapter,
                            struct cxi_hw_caps *caps);

/* Command queue management - following cxi_udp_gen.c pattern */
int cxi_hw_cq_alloc(struct cxi_adapter *adapter,
                    struct cxi_cq *cq, struct cxi_eq *eq, uint32_t size, bool is_tx);
void cxi_hw_cq_free(struct cxi_adapter *adapter,
                    struct cxi_cq *cq);
int cxi_hw_cq_start(struct cxi_adapter *adapter,
                    struct cxi_cq *cq);
void cxi_hw_cq_stop(struct cxi_adapter *adapter,
                    struct cxi_cq *cq);

/* Event queue management */
int cxi_hw_eq_alloc(struct cxi_adapter *adapter,
                    struct cxi_eq *eq, uint32_t size);
void cxi_hw_eq_free(struct cxi_adapter *adapter,
                    struct cxi_eq *eq);
int cxi_hw_eq_start(struct cxi_adapter *adapter,
                    struct cxi_eq *eq);
void cxi_hw_eq_stop(struct cxi_adapter *adapter,
                    struct cxi_eq *eq);

/* Memory descriptor management */
int cxi_hw_md_alloc(struct cxi_adapter *adapter,
                    struct cxi_md *md, void *va, size_t len);
void cxi_hw_md_free(struct cxi_adapter *adapter,
                    struct cxi_md *md);

/* Packet transmission */
int cxi_hw_tx_idc(struct cxi_adapter *adapter,
                  struct cxi_tx_queue *txq,
                  struct rte_mbuf *mbuf);
int cxi_hw_tx_dma(struct cxi_adapter *adapter,
                  struct cxi_tx_queue *txq,
                  struct rte_mbuf *mbuf);

/* Packet reception */
int cxi_hw_rx_setup_buffers(struct cxi_adapter *adapter,
                            struct cxi_rx_queue *rxq);
uint16_t cxi_hw_rx_process_events(struct cxi_adapter *adapter,
                                  struct cxi_rx_queue *rxq,
                                  struct rte_mbuf **rx_pkts,
                                  uint16_t nb_pkts);

/* Statistics */
int cxi_hw_get_stats(struct cxi_adapter *adapter,
                     struct cxi_hw_stats *stats);
void cxi_hw_clear_stats(struct cxi_adapter *adapter);

/* MAC address management - uses libcxi */
int cxi_hw_get_mac_addr(struct cxi_adapter *adapter,
                        struct rte_ether_addr *mac_addr);
int cxi_hw_set_mac_addr(struct cxi_adapter *adapter,
                        const struct rte_ether_addr *mac_addr);

/* Link management - uses libcxi */
int cxi_hw_get_link_info(struct cxi_adapter *adapter,
                         struct rte_eth_link *link);
int cxi_hw_set_link_up(struct cxi_adapter *adapter);
int cxi_hw_set_link_down(struct cxi_adapter *adapter);

/* Promiscuous mode - uses libcxi */
int cxi_hw_set_promiscuous(struct cxi_adapter *adapter, bool enable);
int cxi_hw_set_allmulticast(struct cxi_adapter *adapter, bool enable);

/* MTU management - uses libcxi */
int cxi_hw_set_mtu(struct cxi_adapter *adapter, uint16_t mtu);

/* Interrupt management */
int cxi_hw_enable_interrupts(struct cxi_adapter *adapter);
void cxi_hw_disable_interrupts(struct cxi_adapter *adapter);

/* RSS configuration - uses libcxi */
int cxi_hw_configure_rss(struct cxi_adapter *adapter,
                         struct rte_eth_rss_conf *rss_conf);
int cxi_hw_rss_hash_update(struct cxi_adapter *adapter,
                           struct rte_eth_rss_conf *rss_conf);
int cxi_hw_rss_reta_update(struct cxi_adapter *adapter,
                           struct rte_eth_rss_reta_entry64 *reta_conf,
                           uint16_t reta_size);
int cxi_hw_rss_reta_query(struct cxi_adapter *adapter,
                          struct rte_eth_rss_reta_entry64 *reta_conf,
                          uint16_t reta_size);

/* Utility functions */
static inline bool cxi_is_cassini_2(struct cxi_adapter *adapter)
{
    return adapter->hw_info.is_cassini_2;
}

static inline uint32_t cxi_get_platform_type(struct cxi_adapter *adapter)
{
    return adapter->hw_info.platform_type;
}

/* Hardware doorbell access helpers - only allowed direct hardware access */
static inline void cxi_write_doorbell(void *doorbell_addr, uint64_t value)
{
    rte_write64(value, (volatile void *)doorbell_addr);
}

static inline void cxi_write_doorbell32(void *doorbell_addr, uint32_t value)
{
    rte_write32(value, (volatile void *)doorbell_addr);
}

/* Command submission helpers - uses libcxi doorbell interface */
static inline void cxi_cq_ring_doorbell(struct cxi_cq *cq)
{
    if (cq->cq) {
        cxi_cq_ring(cq->cq);
    }
}

/* Event processing helpers */
static inline bool cxi_eq_has_events(struct cxi_eq *eq)
{
    if (eq->eq) {
        return cxi_eq_get_event(eq->eq) != NULL;
    }
    return false;
}

#endif /* _CXI_HW_H_ */
