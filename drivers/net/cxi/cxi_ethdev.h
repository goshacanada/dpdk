/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Hewlett Packard Enterprise Development LP
 */

#ifndef _CXI_ETHDEV_H_
#define _CXI_ETHDEV_H_

#include <stdint.h>
#include <stdbool.h>

#include <rte_ethdev.h>
#include <rte_ethdev_core.h>
#include <rte_spinlock.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_io.h>
#include <rte_pci.h>

/* Include CXI hardware definitions */
#include <cassini_user_defs.h>
#include <cxi_prov_hw.h>
#include <libcxi.h>

/* Driver version */
#define CXI_PMD_VERSION "1.0.0"

/* Device limits */
#define CXI_MAX_RX_QUEUES    64
#define CXI_MAX_TX_QUEUES    64
#define CXI_MAX_QUEUE_SIZE   4096
#define CXI_MIN_QUEUE_SIZE   64
#define CXI_MAX_PKT_SIZE     9216
#define CXI_MIN_PKT_SIZE     64

/* Hardware constants from CXI definitions */
#define CXI_MAX_CQS          C_NUM_TRANSMIT_CQS
#define CXI_MAX_EQS          C_NUM_EQS
#define CXI_MAX_MDS          1024

/* IDC vs DMA threshold */
#define CXI_IDC_MAX_SIZE     256
#define CXI_DMA_MIN_SIZE     (CXI_IDC_MAX_SIZE + 1)

/* Command queue alignment */
#define CXI_CQ_ALIGNMENT     64

/* Forward declarations */
struct cxi_adapter;
struct cxi_rx_queue;
struct cxi_tx_queue;

/* CXI Memory Descriptor wrapper */
struct cxi_md {
    struct cxi_md *md;          /* CXI memory descriptor */
    void *va;                   /* Virtual address */
    uint64_t iova;              /* IO virtual address */
    size_t len;                 /* Length */
    bool is_mapped;             /* Mapping status */
};

/* CXI Command Queue wrapper */
struct cxi_cq {
    struct cxi_cq *cq;          /* CXI command queue */
    void *cmds;                 /* Command memory */
    void *csr;                  /* CSR memory */
    uint32_t size;              /* Queue size */
    uint32_t head;              /* Head pointer */
    uint32_t tail;              /* Tail pointer */
    bool is_tx;                 /* TX or RX queue */
};

/* CXI Event Queue wrapper */
struct cxi_eq {
    struct cxi_eq *eq;          /* CXI event queue */
    void *events;               /* Event memory */
    struct cxi_md eq_md;        /* Event queue memory descriptor */
    uint32_t size;              /* Queue size */
    uint32_t eqn;               /* Event queue number */
    void (*event_cb)(void *);   /* Event callback */
    void *cb_data;              /* Callback data */
};

/* RX Queue structure */
struct cxi_rx_queue {
    struct cxi_adapter *adapter;
    struct cxi_cq cq;           /* Command queue for RX */
    struct cxi_eq eq;           /* Event queue for RX completions */
    struct rte_mempool *mp;     /* Mempool for RX buffers */
    struct rte_mbuf **rx_bufs;  /* RX buffer array */
    
    uint16_t queue_id;          /* Queue ID */
    uint16_t nb_desc;           /* Number of descriptors */
    uint16_t rx_tail;           /* RX tail pointer */
    uint16_t rx_free_thresh;    /* RX free threshold */
    
    /* Statistics */
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t rx_errors;
    uint64_t rx_dropped;
    
    /* Configuration */
    bool started;
    uint32_t crc_len;
    uint64_t offloads;
};

/* TX Queue structure */
struct cxi_tx_queue {
    struct cxi_adapter *adapter;
    struct cxi_cq cq;           /* Command queue for TX */
    struct cxi_eq eq;           /* Event queue for TX completions */
    struct rte_mbuf **tx_bufs;  /* TX buffer array */
    
    uint16_t queue_id;          /* Queue ID */
    uint16_t nb_desc;           /* Number of descriptors */
    uint16_t tx_tail;           /* TX tail pointer */
    uint16_t tx_free_thresh;    /* TX free threshold */
    
    /* Statistics */
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_errors;
    uint64_t tx_dropped;
    
    /* Configuration */
    bool started;
    uint64_t offloads;
    
    /* IDC vs DMA decision tracking */
    uint32_t force_dma_count;
    uint32_t force_dma_interval;
};

/* Device hardware information */
struct cxi_hw_info {
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t subsystem_vendor_id;
    uint16_t subsystem_device_id;
    uint8_t revision;
    
    /* CXI specific info */
    bool is_cassini_2;
    uint32_t platform_type;
    uint32_t num_pes;
    uint32_t num_vfs;
};

/* Main adapter structure */
struct cxi_adapter {
    struct rte_eth_dev *eth_dev;
    struct rte_pci_device *pci_dev;
    
    /* Hardware access - uses libcxi only */
    struct cxi_hw_info hw_info;

    /* CXI device context - libcxi handles */
    struct cxil_dev *cxil_dev;  /* libcxi device handle */
    struct cxil_lni *lni;       /* Logical Network Interface */
    
    /* Queues */
    struct cxi_rx_queue **rx_queues;
    struct cxi_tx_queue **tx_queues;
    uint16_t num_rx_queues;
    uint16_t num_tx_queues;
    
    /* Device state */
    bool started;
    bool promiscuous;
    bool allmulticast;
    
    /* MAC address */
    struct rte_ether_addr mac_addr;
    
    /* Statistics */
    struct rte_eth_stats stats;
    
    /* Synchronization */
    rte_spinlock_t lock;
    
    /* Memory management */
    struct cxi_md *md_pool;
    uint32_t md_pool_size;
    uint32_t md_pool_used;
    
    /* Configuration */
    uint32_t max_rx_pkt_len;
    uint32_t rx_buf_size;
    
    /* Offload capabilities */
    uint64_t rx_offload_capa;
    uint64_t tx_offload_capa;
    uint64_t rx_queue_offload_capa;
    uint64_t tx_queue_offload_capa;
};

/* Function prototypes */

/* Device operations */
int cxi_dev_configure(struct rte_eth_dev *dev);
int cxi_dev_start(struct rte_eth_dev *dev);
int cxi_dev_stop(struct rte_eth_dev *dev);
int cxi_dev_close(struct rte_eth_dev *dev);
int cxi_dev_reset(struct rte_eth_dev *dev);

/* Queue operations */
int cxi_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
                       uint16_t nb_desc, unsigned int socket_id,
                       const struct rte_eth_rxconf *rx_conf,
                       struct rte_mempool *mp);
int cxi_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
                       uint16_t nb_desc, unsigned int socket_id,
                       const struct rte_eth_txconf *tx_conf);
void cxi_rx_queue_release(struct rte_eth_dev *dev, uint16_t queue_idx);
void cxi_tx_queue_release(struct rte_eth_dev *dev, uint16_t queue_idx);

/* RX/TX functions */
uint16_t cxi_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
                       uint16_t nb_pkts);
uint16_t cxi_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
                       uint16_t nb_pkts);

/* Hardware interface */
int cxi_hw_init(struct cxi_adapter *adapter);
void cxi_hw_cleanup(struct cxi_adapter *adapter);

/* Logging */
extern int cxi_logtype_init;
extern int cxi_logtype_driver;

#define PMD_INIT_LOG(level, fmt, args...) \
    rte_log(RTE_LOG_ ## level, cxi_logtype_init, \
        "%s(): " fmt "\n", __func__, ##args)

#define PMD_DRV_LOG(level, fmt, args...) \
    rte_log(RTE_LOG_ ## level, cxi_logtype_driver, \
        "%s(): " fmt "\n", __func__, ##args)

#endif /* _CXI_ETHDEV_H_ */
