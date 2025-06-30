/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Hewlett Packard Enterprise Development LP
 */

#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_prefetch.h>
#include <rte_atomic.h>
#include <rte_udp.h>

#include "cxi_ethdev.h"
#include "cxi_hw.h"

/* Constants from cxi_udp_gen.c */
#define CXI_IDC_MAX_SIZE        C_MAX_IDC_PAYLOAD_RES
#define CXI_PKT_FORMAT_STD      C_PKT_FORMAT_STD
#define CXI_CSUM_NONE          C_CHECKSUM_CTRL_NONE
#define CXI_CSUM_IP            C_CHECKSUM_CTRL_IP
#define CXI_CSUM_TCP           C_CHECKSUM_CTRL_TCP
#define CXI_CSUM_UDP           C_CHECKSUM_CTRL_UDP

/* Memory address translation macro - matches libcxi standard definition */
#define CXI_VA_TO_IOVA(md, va)  ((md) ? (md)->iova + ((uintptr_t)(va) - (md)->va) : \
                                 rte_mem_virt2iova(va))

/* RX queue setup */
int
cxi_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
                   uint16_t nb_desc, unsigned int socket_id,
                   const struct rte_eth_rxconf *rx_conf,
                   struct rte_mempool *mp)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    struct cxi_rx_queue *rxq;
    int ret;

    PMD_DRV_LOG(DEBUG, "Setting up RX queue %u with %u descriptors",
                queue_idx, nb_desc);

    /* Validate parameters */
    if (queue_idx >= CXI_MAX_RX_QUEUES) {
        PMD_DRV_LOG(ERR, "Invalid RX queue index: %u", queue_idx);
        return -EINVAL;
    }

    if (nb_desc < CXI_MIN_QUEUE_SIZE || nb_desc > CXI_MAX_QUEUE_SIZE) {
        PMD_DRV_LOG(ERR, "Invalid number of RX descriptors: %u", nb_desc);
        return -EINVAL;
    }

    /* Allocate RX queue structure */
    rxq = rte_zmalloc_socket("cxi_rxq", sizeof(*rxq), 0, socket_id);
    if (!rxq) {
        PMD_DRV_LOG(ERR, "Failed to allocate RX queue structure");
        return -ENOMEM;
    }

    /* Initialize RX queue */
    rxq->adapter = adapter;
    rxq->queue_id = queue_idx;
    rxq->nb_desc = nb_desc;
    rxq->mp = mp;
    rxq->rx_free_thresh = rx_conf->rx_free_thresh;
    rxq->offloads = rx_conf->offloads;
    rxq->crc_len = (dev->data->dev_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_KEEP_CRC) ?
                   RTE_ETHER_CRC_LEN : 0;

    /* Allocate RX buffer array */
    rxq->rx_bufs = rte_zmalloc_socket("cxi_rx_bufs",
                                     sizeof(struct rte_mbuf *) * nb_desc,
                                     0, socket_id);
    if (!rxq->rx_bufs) {
        PMD_DRV_LOG(ERR, "Failed to allocate RX buffer array");
        rte_free(rxq);
        return -ENOMEM;
    }

    /* Allocate event queue FIRST - following cxi_udp_gen.c pattern */
    ret = cxi_hw_eq_alloc(adapter, &rxq->eq, nb_desc);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to allocate RX event queue");
        goto setup_error;
    }

    /* Allocate command queue with EQ reference - following cxi_udp_gen.c pattern */
    ret = cxi_hw_cq_alloc(adapter, &rxq->cq, &rxq->eq, nb_desc, false);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to allocate RX command queue");
        cxi_hw_eq_free(adapter, &rxq->eq);
        goto setup_error;
    }

    /* Store queue in adapter */
    if (!adapter->rx_queues) {
        adapter->rx_queues = rte_zmalloc("cxi_rx_queues",
                                        sizeof(struct cxi_rx_queue *) * CXI_MAX_RX_QUEUES,
                                        0);
        if (!adapter->rx_queues) {
            PMD_DRV_LOG(ERR, "Failed to allocate RX queue array");
            cxi_hw_eq_free(adapter, &rxq->eq);
            cxi_hw_cq_free(adapter, &rxq->cq);
            goto setup_error;
        }
    }

    adapter->rx_queues[queue_idx] = rxq;
    dev->data->rx_queues[queue_idx] = rxq;

    PMD_DRV_LOG(INFO, "RX queue %u setup completed", queue_idx);
    return 0;

setup_error:
    rte_free(rxq->rx_bufs);
    rte_free(rxq);
    return ret;
}

/* TX queue setup */
int
cxi_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
                   uint16_t nb_desc, unsigned int socket_id,
                   const struct rte_eth_txconf *tx_conf)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    struct cxi_tx_queue *txq;
    int ret;

    PMD_DRV_LOG(DEBUG, "Setting up TX queue %u with %u descriptors",
                queue_idx, nb_desc);

    /* Validate parameters */
    if (queue_idx >= CXI_MAX_TX_QUEUES) {
        PMD_DRV_LOG(ERR, "Invalid TX queue index: %u", queue_idx);
        return -EINVAL;
    }

    if (nb_desc < CXI_MIN_QUEUE_SIZE || nb_desc > CXI_MAX_QUEUE_SIZE) {
        PMD_DRV_LOG(ERR, "Invalid number of TX descriptors: %u", nb_desc);
        return -EINVAL;
    }

    /* Allocate TX queue structure */
    txq = rte_zmalloc_socket("cxi_txq", sizeof(*txq), 0, socket_id);
    if (!txq) {
        PMD_DRV_LOG(ERR, "Failed to allocate TX queue structure");
        return -ENOMEM;
    }

    /* Initialize TX queue */
    txq->adapter = adapter;
    txq->queue_id = queue_idx;
    txq->nb_desc = nb_desc;
    txq->tx_free_thresh = tx_conf->tx_free_thresh;
    txq->offloads = tx_conf->offloads;
    txq->force_dma_interval = nb_desc / 8; /* Force DMA every 1/8 of queue */
    txq->force_dma_count = txq->force_dma_interval;

    /* Initialize credits - following cxi_udp_gen.c pattern */
    rte_atomic32_init(&txq->tx_credits);
    rte_atomic32_set(&txq->tx_credits, nb_desc);

    /* Allocate TX buffer array */
    txq->tx_bufs = rte_zmalloc_socket("cxi_tx_bufs",
                                     sizeof(struct rte_mbuf *) * nb_desc,
                                     0, socket_id);
    if (!txq->tx_bufs) {
        PMD_DRV_LOG(ERR, "Failed to allocate TX buffer array");
        rte_free(txq);
        return -ENOMEM;
    }

    /* Allocate event queue FIRST - following cxi_udp_gen.c pattern */
    ret = cxi_hw_eq_alloc(adapter, &txq->eq, nb_desc);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to allocate TX event queue");
        goto setup_error;
    }

    /* Allocate command queue with EQ reference - following cxi_udp_gen.c pattern */
    ret = cxi_hw_cq_alloc(adapter, &txq->cq, &txq->eq, nb_desc, true);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to allocate TX command queue");
        cxi_hw_eq_free(adapter, &txq->eq);
        goto setup_error;
    }

    /* Store queue in adapter */
    if (!adapter->tx_queues) {
        adapter->tx_queues = rte_zmalloc("cxi_tx_queues",
                                        sizeof(struct cxi_tx_queue *) * CXI_MAX_TX_QUEUES,
                                        0);
        if (!adapter->tx_queues) {
            PMD_DRV_LOG(ERR, "Failed to allocate TX queue array");
            cxi_hw_eq_free(adapter, &txq->eq);
            cxi_hw_cq_free(adapter, &txq->cq);
            goto setup_error;
        }
    }

    adapter->tx_queues[queue_idx] = txq;
    dev->data->tx_queues[queue_idx] = txq;

    PMD_DRV_LOG(INFO, "TX queue %u setup completed", queue_idx);
    return 0;

setup_error:
    rte_free(txq->tx_bufs);
    rte_free(txq);
    return ret;
}

/* RX queue release */
void
cxi_rx_queue_release(struct rte_eth_dev *dev, uint16_t queue_idx)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    struct cxi_rx_queue *rxq;

    if (queue_idx >= CXI_MAX_RX_QUEUES || !adapter->rx_queues)
        return;

    rxq = adapter->rx_queues[queue_idx];
    if (!rxq)
        return;

    PMD_DRV_LOG(DEBUG, "Releasing RX queue %u", queue_idx);

    /* Stop queue if started */
    if (rxq->started) {
        cxi_hw_cq_stop(adapter, &rxq->cq);
        cxi_hw_eq_stop(adapter, &rxq->eq);
    }

    /* Free hardware resources */
    cxi_hw_eq_free(adapter, &rxq->eq);
    cxi_hw_cq_free(adapter, &rxq->cq);

    /* Free software resources */
    if (rxq->rx_bufs) {
        /* Free any remaining mbufs */
        for (uint16_t i = 0; i < rxq->nb_desc; i++) {
            if (rxq->rx_bufs[i]) {
                rte_pktmbuf_free(rxq->rx_bufs[i]);
                rxq->rx_bufs[i] = NULL;
            }
        }
        rte_free(rxq->rx_bufs);
    }

    rte_free(rxq);
    adapter->rx_queues[queue_idx] = NULL;
    dev->data->rx_queues[queue_idx] = NULL;
}

/* TX queue release */
void
cxi_tx_queue_release(struct rte_eth_dev *dev, uint16_t queue_idx)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    struct cxi_tx_queue *txq;

    if (queue_idx >= CXI_MAX_TX_QUEUES || !adapter->tx_queues)
        return;

    txq = adapter->tx_queues[queue_idx];
    if (!txq)
        return;

    PMD_DRV_LOG(DEBUG, "Releasing TX queue %u", queue_idx);

    /* Stop queue if started */
    if (txq->started) {
        cxi_hw_cq_stop(adapter, &txq->cq);
        cxi_hw_eq_stop(adapter, &txq->eq);
    }

    /* Free hardware resources */
    cxi_hw_eq_free(adapter, &txq->eq);
    cxi_hw_cq_free(adapter, &txq->cq);

    /* Free software resources */
    if (txq->tx_bufs) {
        /* Free any remaining mbufs */
        for (uint16_t i = 0; i < txq->nb_desc; i++) {
            if (txq->tx_bufs[i]) {
                rte_pktmbuf_free(txq->tx_bufs[i]);
                txq->tx_bufs[i] = NULL;
            }
        }
        rte_free(txq->tx_bufs);
    }

    rte_free(txq);
    adapter->tx_queues[queue_idx] = NULL;
    dev->data->tx_queues[queue_idx] = NULL;
}

/* Helper function to decide between IDC and DMA */
static inline bool
cxi_should_use_idc(struct cxi_tx_queue *txq, struct rte_mbuf *mbuf)
{
    /* Use IDC for small, unfragmented packets */
    if (mbuf->nb_segs > 1) {
        /* Fragmented packet - use DMA */
        return false;
    }

    if (mbuf->pkt_len > CXI_IDC_MAX_SIZE) {
        /* Packet too large for IDC */
        return false;
    }

    /* Check force DMA counter to avoid too many consecutive IDC */
    if (--txq->force_dma_count == 0) {
        /* Force DMA to balance the load */
        txq->force_dma_count = txq->force_dma_interval;
        return false;
    }

    return true;
}

/* Receive packets */
uint16_t
cxi_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
    struct cxi_rx_queue *rxq = rx_queue;
    struct cxi_adapter *adapter = rxq->adapter;
    uint16_t nb_rx = 0;

    /* Process events from event queue */
    nb_rx = cxi_hw_rx_process_events(adapter, rxq, rx_pkts, nb_pkts);

    /* Update statistics */
    rxq->rx_packets += nb_rx;
    for (uint16_t i = 0; i < nb_rx; i++) {
        rxq->rx_bytes += rx_pkts[i]->pkt_len;
    }

    return nb_rx;
}

/* Transmit packets */
uint16_t
cxi_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
    struct cxi_tx_queue *txq = tx_queue;
    struct cxi_adapter *adapter = txq->adapter;
    uint16_t nb_tx = 0;
    int ret;

    /* Process completions first to free up credits */
    cxi_hw_tx_process_events(adapter, txq);

    for (uint16_t i = 0; i < nb_pkts; i++) {
        struct rte_mbuf *mbuf = tx_pkts[i];

        /* Prefetch next mbuf */
        if (i + 1 < nb_pkts)
            rte_prefetch0(tx_pkts[i + 1]);

        /* Check if we have credits available */
        if (rte_atomic32_read(&txq->tx_credits) == 0) {
            /* Try to process more completions */
            cxi_hw_tx_process_events(adapter, txq);
            if (rte_atomic32_read(&txq->tx_credits) == 0) {
                /* Still no credits, stop transmitting */
                break;
            }
        }

        /* Decide between IDC and DMA based on packet size and fragmentation */
        if (cxi_should_use_idc(txq, mbuf)) {
            ret = cxi_hw_tx_idc(adapter, txq, mbuf);
        } else {
            ret = cxi_hw_tx_dma(adapter, txq, mbuf);
            txq->force_dma_count = txq->force_dma_interval;
        }

        if (ret) {
            /* Failed to transmit */
            if (ret != -EAGAIN) {
                txq->tx_errors++;
            }
            break;
        }

        /* Update statistics */
        txq->tx_packets++;
        txq->tx_bytes += mbuf->pkt_len;
        nb_tx++;
    }

    /* Ring doorbell if we transmitted any packets */
    if (nb_tx > 0) {
        cxi_cq_ring(txq->cq.cq);
    }

    return nb_tx;
}

/* Hardware-specific TX IDC implementation */
int
cxi_hw_tx_idc(struct cxi_adapter *adapter,
              struct cxi_tx_queue *txq,
              struct rte_mbuf *mbuf)
{
    struct c_idc_eth_cmd idc_cmd = {0};
    int ret;

    PMD_DRV_LOG(DEBUG, "Transmitting packet via IDC, len: %u", mbuf->pkt_len);

    /* Check if we have credits available */
    if (rte_atomic32_read(&txq->tx_credits) == 0) {
        PMD_DRV_LOG(DEBUG, "No TX credits available");
        return -EAGAIN;
    }

    /* Set up IDC ethernet command - following cxi_udp_gen.c pattern */
    idc_cmd.fmt = C_PKT_FORMAT_STD;
    idc_cmd.length = sizeof(struct c_idc_eth_cmd) + mbuf->pkt_len;
    idc_cmd.flow_hash = txq->queue_id;     /* Use queue ID as flow hash */
    idc_cmd.checksum_ctrl = C_CHECKSUM_CTRL_NONE;
    idc_cmd.eq = txq->eq.eqn;
    idc_cmd.user_ptr = (uintptr_t)mbuf;    /* Store mbuf for completion */

    /* Handle checksum offload */
    if (mbuf->ol_flags & (RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_UDP_CKSUM |
                         RTE_MBUF_F_TX_TCP_CKSUM)) {
        if (mbuf->ol_flags & RTE_MBUF_F_TX_TCP_CKSUM) {
            idc_cmd.checksum_ctrl = C_CHECKSUM_CTRL_TCP;
            idc_cmd.checksum_offset = (mbuf->l2_len + mbuf->l3_len +
                                      offsetof(struct rte_tcp_hdr, cksum)) / 2;
        } else if (mbuf->ol_flags & RTE_MBUF_F_TX_UDP_CKSUM) {
            idc_cmd.checksum_ctrl = C_CHECKSUM_CTRL_UDP;
            idc_cmd.checksum_offset = (mbuf->l2_len + mbuf->l3_len +
                                      offsetof(struct rte_udp_hdr, dgram_cksum)) / 2;
        } else {
            idc_cmd.checksum_ctrl = C_CHECKSUM_CTRL_IP;
        }
        idc_cmd.checksum_start = mbuf->l2_len / 2;
    }

    /* Submit IDC command with packet data */
    if (txq->cq.cq) {
        ret = cxi_cq_emit_idc_eth(txq->cq.cq, &idc_cmd,
                                 rte_pktmbuf_mtod(mbuf, void *),
                                 mbuf->pkt_len);
    } else {
        /* Fallback for testing */
        ret = 0;
    }

    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to emit IDC command: %d", ret);
        return ret;
    }

    /* Consume a credit */
    rte_atomic32_dec(&txq->tx_credits);

    return 0;
}

/* Hardware-specific TX DMA implementation */
int
cxi_hw_tx_dma(struct cxi_adapter *adapter,
              struct cxi_tx_queue *txq,
              struct rte_mbuf *mbuf)
{
    struct c_dma_eth_cmd dma_cmd = {0};
    struct rte_mbuf *seg;
    uint8_t seg_count = 0;
    int ret;

    PMD_DRV_LOG(DEBUG, "Transmitting packet via DMA, len: %u, segs: %u",
                mbuf->pkt_len, mbuf->nb_segs);

    /* Check if we have credits available */
    if (rte_atomic32_read(&txq->tx_credits) == 0) {
        PMD_DRV_LOG(DEBUG, "No TX credits available");
        return -EAGAIN;
    }

    /* Set up DMA ethernet command - following cxi_udp_gen.c pattern */
    dma_cmd.read_lac = adapter->tx_md->lac;  /* Critical: LAC from memory descriptor */
    dma_cmd.fmt = C_PKT_FORMAT_STD;
    dma_cmd.flow_hash = txq->queue_id;     /* Use queue ID as flow hash */
    dma_cmd.checksum_ctrl = C_CHECKSUM_CTRL_NONE;
    dma_cmd.eq = txq->eq.eqn;
    dma_cmd.total_len = mbuf->pkt_len;
    dma_cmd.user_ptr = (uintptr_t)mbuf;    /* Store mbuf for completion */

    /* Handle checksum offload */
    if (mbuf->ol_flags & (RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_UDP_CKSUM |
                         RTE_MBUF_F_TX_TCP_CKSUM)) {
        if (mbuf->ol_flags & RTE_MBUF_F_TX_TCP_CKSUM) {
            dma_cmd.checksum_ctrl = C_CHECKSUM_CTRL_TCP;
            dma_cmd.checksum_offset = (mbuf->l2_len + mbuf->l3_len +
                                      offsetof(struct rte_tcp_hdr, cksum)) / 2;
        } else if (mbuf->ol_flags & RTE_MBUF_F_TX_UDP_CKSUM) {
            dma_cmd.checksum_ctrl = C_CHECKSUM_CTRL_UDP;
            dma_cmd.checksum_offset = (mbuf->l2_len + mbuf->l3_len +
                                      offsetof(struct rte_udp_hdr, dgram_cksum)) / 2;
        } else {
            dma_cmd.checksum_ctrl = C_CHECKSUM_CTRL_IP;
        }
        dma_cmd.checksum_start = mbuf->l2_len / 2;
    }

    /* Build scatter-gather list using mapped IOVA addresses */
    seg = mbuf;
    while (seg && seg_count < 5) { /* CXI supports up to 5 segments (C_MAX_ETH_FRAGS) */
        /* Use CXI_VA_TO_IOVA macro like cxi_udp_gen.c */
        dma_cmd.addr[seg_count] = CXI_VA_TO_IOVA(adapter->tx_md,
                                                rte_pktmbuf_mtod(seg, void *));
        dma_cmd.len[seg_count] = seg->data_len;
        seg_count++;
        seg = seg->next;
    }

    if (seg) {
        PMD_DRV_LOG(ERR, "Too many segments: %u", mbuf->nb_segs);
        return -EINVAL;
    }

    dma_cmd.num_segments = seg_count;

    /* Submit DMA command */
    if (txq->cq.cq) {
        ret = cxi_cq_emit_dma_eth(txq->cq.cq, &dma_cmd);
    } else {
        /* Fallback for testing */
        ret = 0;
    }

    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to emit DMA command: %d", ret);
        return ret;
    }

    /* Consume a credit */
    rte_atomic32_dec(&txq->tx_credits);

    return 0;
}

/* Process TX completion events - following cxi_udp_gen.c pattern */
uint16_t
cxi_hw_tx_process_events(struct cxi_adapter *adapter,
                         struct cxi_tx_queue *txq)
{
    const union c_event *event;
    uint16_t completed = 0;
    int event_count = 0;

    if (!txq->eq.eq) {
        return 0;
    }

    /* Process completion events */
    while ((event = cxi_eq_get_event(txq->eq.eq))) {
        struct rte_mbuf *mbuf;

        /* Validate event */
        if (event->hdr.event_size != C_EVENT_SIZE_16_BYTE) {
            PMD_DRV_LOG(ERR, "Unexpected event size: %u", event->hdr.event_size);
            break;
        }

        if (event->hdr.event_type != C_EVENT_SEND) {
            PMD_DRV_LOG(ERR, "Unexpected event type: %u", event->hdr.event_type);
            break;
        }

        if (event->init_short.return_code != C_RC_OK) {
            PMD_DRV_LOG(ERR, "TX completion error: %u",
                        event->init_short.return_code);
            txq->tx_errors++;
        }

        /* Retrieve mbuf from user_ptr */
        mbuf = (struct rte_mbuf *)event->init_short.user_ptr;
        if (mbuf) {
            /* Free the transmitted mbuf */
            rte_pktmbuf_free(mbuf);
            completed++;
        }

        /* Return a credit - following cxi_udp_gen.c pattern */
        rte_atomic32_inc(&txq->tx_credits);

        /* Limit event processing per call */
        event_count++;
        if (event_count >= 16) {
            break;
        }
    }

    /* Acknowledge processed events */
    if (event_count > 0) {
        cxi_eq_ack_events(txq->eq.eq);
    }

    return completed;
}

/* Hardware-specific RX buffer setup */
int
cxi_hw_rx_setup_buffers(struct cxi_adapter *adapter,
                        struct cxi_rx_queue *rxq)
{
    struct rte_mbuf *mbuf;
    uint16_t i;

    PMD_DRV_LOG(DEBUG, "Setting up RX buffers for queue %u", rxq->queue_id);

    /* Allocate and post RX buffers */
    for (i = 0; i < rxq->nb_desc; i++) {
        mbuf = rte_pktmbuf_alloc(rxq->mp);
        if (!mbuf) {
            PMD_DRV_LOG(ERR, "Failed to allocate RX buffer");
            return -ENOMEM;
        }

        rxq->rx_bufs[i] = mbuf;

        /* Post buffer to hardware */
        /* Implementation would submit receive descriptors here */
    }

    RTE_SET_USED(adapter);
    return 0;
}

/* Hardware-specific RX event processing */
uint16_t
cxi_hw_rx_process_events(struct cxi_adapter *adapter,
                         struct cxi_rx_queue *rxq,
                         struct rte_mbuf **rx_pkts,
                         uint16_t nb_pkts)
{
    uint16_t nb_rx = 0;

    /* Process events from the event queue */
    /* This is a placeholder - real implementation would:
     * 1. Check for events in the EQ
     * 2. Process completion events
     * 3. Extract received packets
     * 4. Allocate new RX buffers
     */

    RTE_SET_USED(adapter);
    RTE_SET_USED(rxq);
    RTE_SET_USED(rx_pkts);
    RTE_SET_USED(nb_pkts);

    return nb_rx;
}
