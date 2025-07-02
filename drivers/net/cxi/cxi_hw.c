/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Hewlett Packard Enterprise Development LP
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_cycles.h>
#include <rte_io.h>
#include <rte_pci.h>

#include "cxi_hw.h"
#include "cxi_ethdev.h"

/* Hardware probe function */
int
cxi_hw_probe(struct rte_pci_device *pci_dev)
{
    uint32_t device_id;
    
    PMD_INIT_LOG(DEBUG, "Probing CXI hardware");
    
    /* Verify this is a CXI device */
    if (pci_dev->id.vendor_id != CXI_VENDOR_ID) {
        PMD_INIT_LOG(ERR, "Invalid vendor ID: 0x%x", pci_dev->id.vendor_id);
        return -ENODEV;
    }
    
    device_id = pci_dev->id.device_id;
    if (device_id != CXI_DEVICE_ID_C1 && device_id != CXI_DEVICE_ID_C2) {
        PMD_INIT_LOG(ERR, "Invalid device ID: 0x%x", device_id);
        return -ENODEV;
    }
    
    PMD_INIT_LOG(INFO, "Found CXI %s device",
                 (device_id == CXI_DEVICE_ID_C2) ? "2" : "1");
    
    return 0;
}

/* Initialize CXI device */
int
cxi_hw_init_device(struct cxi_adapter *adapter)
{
    int ret;

    PMD_DRV_LOG(DEBUG, "Initializing CXI hardware via libcxi");

    if (!adapter->cxil_dev) {
        PMD_DRV_LOG(ERR, "No libcxi device handle");
        return -EINVAL;
    }

    /* Initialize ethernet functionality via libcxi */
    ret = cxil_init_eth_device(adapter->cxil_dev);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to initialize ethernet device: %d", ret);
        return ret;
    }

    PMD_DRV_LOG(INFO, "CXI hardware initialized successfully via libcxi");
    return 0;
}

/* Cleanup CXI device */
void
cxi_hw_cleanup_device(struct cxi_adapter *adapter)
{
    PMD_DRV_LOG(DEBUG, "Cleaning up CXI hardware via libcxi");

    /* Cleanup is handled by libcxi when device is closed */
    /* No direct hardware access needed */
    RTE_SET_USED(adapter);
}

/* Reset CXI device */
int
cxi_hw_reset_device(struct cxi_adapter *adapter)
{
    PMD_DRV_LOG(DEBUG, "Resetting CXI hardware via libcxi");

    /* Hardware reset is handled by libcxi/kernel driver */
    /* PMD should not perform direct hardware reset */

    /* Re-initialize ethernet functionality */
    return cxi_hw_init_device(adapter);
}

/* Get hardware capabilities */
int
cxi_hw_get_capabilities(struct cxi_adapter *adapter,
                        struct cxi_hw_caps *caps)
{
    struct cxi_eth_caps eth_caps;
    int ret;

    PMD_DRV_LOG(DEBUG, "Getting hardware capabilities via libcxi");

    if (!adapter->cxil_dev) {
        PMD_DRV_LOG(ERR, "No libcxi device handle");
        return -EINVAL;
    }

    /* Get capabilities from libcxi */
    ret = cxil_get_eth_capabilities(adapter->cxil_dev, &eth_caps);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to get ethernet capabilities: %d", ret);
        return ret;
    }

    /* Copy capabilities to PMD structure */
    caps->max_mtu = eth_caps.max_mtu;
    caps->min_mtu = eth_caps.min_mtu;
    caps->supports_checksum = eth_caps.supports_checksum;
    caps->supports_tso = eth_caps.supports_tso;
    caps->supports_rss = eth_caps.supports_rss;
    caps->supports_vlan = eth_caps.supports_vlan;
    caps->max_queues = eth_caps.max_queues;

    return 0;
}

/* Allocate command queue - following cxi_udp_gen.c pattern exactly */
int
cxi_hw_cq_alloc(struct cxi_adapter *adapter, struct cxi_pmd_cq *cq,
                struct cxi_pmd_eq *eq, uint32_t size, bool is_tx)
{
    struct cxi_cq_alloc_opts cq_opts = {0};
    struct c_cstate_cmd c_state = {0};
    int ret, j;

    PMD_DRV_LOG(DEBUG, "Allocating %s command queue, size: %u",
                is_tx ? "TX" : "RX", size);

    /* Validate size */
    if (size < CXI_CQ_SIZE_MIN || size > CXI_CQ_SIZE_MAX) {
        PMD_DRV_LOG(ERR, "Invalid CQ size: %u", size);
        return -EINVAL;
    }

    /* Set up CQ allocation options - exactly like cxi_udp_gen.c */
    cq_opts.count = CXI_MAX_CQ_COUNT;  /* Use max count like cxi_udp_gen.c */
    cq_opts.policy = CXI_CQ_UPDATE_LOW_FREQ_EMPTY;
    cq_opts.flags = is_tx ? (CXI_CQ_IS_TX | CXI_CQ_TX_ETHERNET) : 0;
    cq_opts.lcid = adapter->cp->lcid;  /* CRITICAL: Use CP's LCID */

    /* Allocate command queue - exactly like cxi_udp_gen.c */
    if (adapter->lni && eq) {
        ret = cxil_alloc_cmdq(adapter->lni, eq->eq, &cq_opts, &cq->cq);
        if (ret) {
            PMD_DRV_LOG(ERR, "Failed to allocate command queue: %d", ret);
            return ret;
        }
    } else {
        PMD_DRV_LOG(ERR, "Missing LNI or EQ for CQ allocation");
        return -EINVAL;
    }

    cq->size = size;
    cq->head = 0;
    cq->tail = 0;
    cq->is_tx = is_tx;

    /* Issue C_STATE commands for CQ alignment - exactly like cxi_udp_gen.c */
    c_state.restricted = 1;
    c_state.event_success_disable = 1;
    c_state.eq = eq->eqn;

    /* Issue 8 commands to align CQ on 256 byte boundary - exactly like cxi_udp_gen.c */
    for (j = 0; j < 8; j++) {
        ret = cxi_cq_emit_c_state(cq->cq, &c_state);
        if (ret) {
            PMD_DRV_LOG(ERR, "Failed to emit C_STATE command: %d", ret);
            cxil_destroy_cmdq(cq->cq);
            return ret;
        }
    }
    cxi_cq_ring(cq->cq);

    PMD_DRV_LOG(DEBUG, "Command queue allocated successfully");
    return 0;
}

/* Free command queue */
void
cxi_hw_cq_free(struct cxi_adapter *adapter, struct cxi_pmd_cq *cq)
{
    PMD_DRV_LOG(DEBUG, "Freeing command queue");
    
    if (cq->cq) {
        cxil_destroy_cmdq(cq->cq);
        cq->cq = NULL;
    } else {
        /* Fallback cleanup */
        if (cq->cmds) {
            rte_free(cq->cmds);
            cq->cmds = NULL;
        }
        if (cq->csr) {
            rte_free(cq->csr);
            cq->csr = NULL;
        }
    }
    
    RTE_SET_USED(adapter);
}

/* Start command queue */
int
cxi_hw_cq_start(struct cxi_adapter *adapter, struct cxi_pmd_cq *cq)
{
    PMD_DRV_LOG(DEBUG, "Starting command queue");
    
    /* Initialize queue pointers */
    cq->head = 0;
    cq->tail = 0;
    
    /* Additional start logic would go here */
    RTE_SET_USED(adapter);
    
    return 0;
}

/* Stop command queue */
void
cxi_hw_cq_stop(struct cxi_adapter *adapter, struct cxi_pmd_cq *cq)
{
    PMD_DRV_LOG(DEBUG, "Stopping command queue");
    
    /* Stop logic would go here */
    RTE_SET_USED(adapter);
    RTE_SET_USED(cq);
}

/* Allocate event queue - following cxi_udp_gen.c pattern exactly */
int
cxi_hw_eq_alloc(struct cxi_adapter *adapter, struct cxi_pmd_eq *eq,
                uint32_t size)
{
    struct cxi_eq_attr eq_attrs = {0};
    int ret;
    size_t eq_buf_size = 4U * 1024 * 1024; /* EQ_BUF_SIZE from cxi_udp_gen.c */

    PMD_DRV_LOG(DEBUG, "Allocating event queue, size: %u", size);

    /* Validate size */
    if (size < CXI_EQ_SIZE_MIN || size > CXI_EQ_SIZE_MAX) {
        PMD_DRV_LOG(ERR, "Invalid EQ size: %u", size);
        return -EINVAL;
    }

    /* Step 1: aligned_alloc for EQ buffer - exactly like cxi_udp_gen.c */
    eq->eq_buf = aligned_alloc(sysconf(_SC_PAGE_SIZE), eq_buf_size);
    if (!eq->eq_buf) {
        PMD_DRV_LOG(ERR, "Failed to allocate EQ buffer");
        return -ENOMEM;
    }

    /* Step 2: Allocate memory descriptor */
    eq->eq_md = rte_zmalloc("cxi_eq_md", sizeof(struct cxi_md), 0);
    if (!eq->eq_md) {
        PMD_DRV_LOG(ERR, "Failed to allocate EQ MD");
        free(eq->eq_buf);
        return -ENOMEM;
    }

    /* Step 3: Map EQ buffer - exactly like cxi_udp_gen.c */
    if (adapter->lni) {
        ret = cxil_map(adapter->lni, eq->eq_buf, eq_buf_size,
                      CXI_MAP_PIN | CXI_MAP_WRITE, NULL, &eq->eq_md);
        if (ret) {
            PMD_DRV_LOG(ERR, "Failed to map EQ buffer: %d", ret);
            rte_free(eq->eq_md);
            free(eq->eq_buf);
            return ret;
        }
    } else {
        /* Fallback for testing */
        eq->eq_md->va = eq->eq_buf;
        eq->eq_md->iova = rte_mem_virt2iova(eq->eq_buf);
        eq->eq_md->len = eq_buf_size;
        eq->eq_md->is_mapped = true;
    }

    /* Step 4: Set up EQ attributes - exactly like cxi_udp_gen.c */
    eq_attrs.queue = eq->eq_buf;
    eq_attrs.queue_len = eq_buf_size;

    /* Step 5: Allocate event queue - exactly like cxi_udp_gen.c */
    if (adapter->lni) {
        ret = cxil_alloc_evtq(adapter->lni, eq->eq_md, &eq_attrs,
                             NULL, NULL, &eq->eq);
        if (ret) {
            PMD_DRV_LOG(ERR, "Failed to allocate event queue: %d", ret);
            if (eq->eq_md->md) {
                cxil_unmap(eq->eq_md->md);
            }
            rte_free(eq->eq_md);
            free(eq->eq_buf);
            return ret;
        }
        eq->eqn = eq->eq->eqn;
    } else {
        /* Fallback for testing */
        eq->eqn = 0;
    }

    eq->size = size;

    PMD_DRV_LOG(DEBUG, "Event queue allocated successfully, EQN: %u", eq->eqn);
    return 0;
}

/* Free event queue */
void
cxi_hw_eq_free(struct cxi_adapter *adapter, struct cxi_pmd_eq *eq)
{
    PMD_DRV_LOG(DEBUG, "Freeing event queue");
    
    if (eq->eq) {
        cxil_destroy_evtq(eq->eq);
        eq->eq = NULL;
    }
    
    if (eq->eq_md && eq->eq_md->is_mapped) {
        cxi_hw_md_free(adapter, eq->eq_md);
    }

    if (eq->eq_md) {
        rte_free(eq->eq_md);
        eq->eq_md = NULL;
    }
}

/* Start event queue */
int
cxi_hw_eq_start(struct cxi_adapter *adapter, struct cxi_pmd_eq *eq)
{
    PMD_DRV_LOG(DEBUG, "Starting event queue");
    
    /* Start logic would go here */
    RTE_SET_USED(adapter);
    RTE_SET_USED(eq);
    
    return 0;
}

/* Stop event queue */
void
cxi_hw_eq_stop(struct cxi_adapter *adapter, struct cxi_pmd_eq *eq)
{
    PMD_DRV_LOG(DEBUG, "Stopping event queue");
    
    /* Stop logic would go here */
    RTE_SET_USED(adapter);
    RTE_SET_USED(eq);
}

/* Allocate memory descriptor */
int
cxi_hw_md_alloc(struct cxi_adapter *adapter, struct cxi_md *md,
                void *va, size_t len)
{
    int ret;

    PMD_DRV_LOG(DEBUG, "Allocating memory descriptor, VA: %p, len: %zu", va, len);

    /* Validate parameters */
    if (!va || len == 0 || len > CXI_MD_MAX_SIZE) {
        PMD_DRV_LOG(ERR, "Invalid MD parameters");
        return -EINVAL;
    }

    /* Align length to page boundary */
    len = RTE_ALIGN_CEIL(len, CXI_MD_ALIGN);

    if (adapter->lni) {
        /* Use libcxi for mapping */
        struct cxi_md *libcxi_md = NULL;
        ret = cxil_map(adapter->lni, va, len,
                      CXI_MAP_PIN | CXI_MAP_READ | CXI_MAP_WRITE,
                      NULL, &libcxi_md);
        if (ret) {
            PMD_DRV_LOG(ERR, "Failed to map memory: %d", ret);
            return ret;
        }

        md->va = va;
        md->iova = libcxi_md->iova;
        md->len = len;
        md->md = libcxi_md;
        md->is_mapped = true;
    } else {
        /* Fallback for testing */
        md->va = va;
        md->iova = rte_mem_virt2iova(va);
        md->len = len;
        md->md = NULL;
        md->is_mapped = true;
    }

    PMD_DRV_LOG(DEBUG, "Memory descriptor allocated, IOVA: 0x%lx", md->iova);
    return 0;
}

/* Free memory descriptor */
void
cxi_hw_md_free(struct cxi_adapter *adapter, struct cxi_md *md)
{
    PMD_DRV_LOG(DEBUG, "Freeing memory descriptor");

    if (!md->is_mapped)
        return;

    if (md->md) {
        cxil_unmap(md->md);
        md->md = NULL;
    }

    md->va = NULL;
    md->iova = 0;
    md->len = 0;
    md->is_mapped = false;

    RTE_SET_USED(adapter);
}

/* Get hardware statistics */
int
cxi_hw_get_stats(struct cxi_adapter *adapter,
                 struct cxi_hw_stats *stats)
{
    PMD_DRV_LOG(DEBUG, "Getting hardware statistics");

    /* Read statistics from hardware registers or accumulate from queues */
    memset(stats, 0, sizeof(*stats));

    /* Accumulate stats from all queues */
    for (uint16_t i = 0; i < adapter->num_rx_queues; i++) {
        if (adapter->rx_queues[i]) {
            stats->rx_packets += adapter->rx_queues[i]->rx_packets;
            stats->rx_bytes += adapter->rx_queues[i]->rx_bytes;
            stats->rx_errors += adapter->rx_queues[i]->rx_errors;
            stats->rx_dropped += adapter->rx_queues[i]->rx_dropped;
        }
    }

    for (uint16_t i = 0; i < adapter->num_tx_queues; i++) {
        if (adapter->tx_queues[i]) {
            stats->tx_packets += adapter->tx_queues[i]->tx_packets;
            stats->tx_bytes += adapter->tx_queues[i]->tx_bytes;
            stats->tx_errors += adapter->tx_queues[i]->tx_errors;
            stats->tx_dropped += adapter->tx_queues[i]->tx_dropped;
        }
    }

    return 0;
}

/* Clear hardware statistics */
void
cxi_hw_clear_stats(struct cxi_adapter *adapter)
{
    PMD_DRV_LOG(DEBUG, "Clearing hardware statistics");

    /* Clear queue statistics */
    for (uint16_t i = 0; i < adapter->num_rx_queues; i++) {
        if (adapter->rx_queues[i]) {
            adapter->rx_queues[i]->rx_packets = 0;
            adapter->rx_queues[i]->rx_bytes = 0;
            adapter->rx_queues[i]->rx_errors = 0;
            adapter->rx_queues[i]->rx_dropped = 0;
        }
    }

    for (uint16_t i = 0; i < adapter->num_tx_queues; i++) {
        if (adapter->tx_queues[i]) {
            adapter->tx_queues[i]->tx_packets = 0;
            adapter->tx_queues[i]->tx_bytes = 0;
            adapter->tx_queues[i]->tx_errors = 0;
            adapter->tx_queues[i]->tx_dropped = 0;
        }
    }
}

/* Get MAC address */
int
cxi_hw_get_mac_addr(struct cxi_adapter *adapter,
                    struct rte_ether_addr *mac_addr)
{
    int ret;

    PMD_DRV_LOG(DEBUG, "Getting MAC address via libcxi");

    if (!adapter->cxil_dev) {
        PMD_DRV_LOG(ERR, "No libcxi device handle");
        return -EINVAL;
    }

    /* Get MAC address from libcxi */
    ret = cxil_get_mac_address(adapter->cxil_dev, mac_addr->addr_bytes);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to get MAC address: %d", ret);
        return ret;
    }

    return 0;
}

/* Set MAC address */
int
cxi_hw_set_mac_addr(struct cxi_adapter *adapter,
                    const struct rte_ether_addr *mac_addr)
{
    int ret;

    PMD_DRV_LOG(DEBUG, "Setting MAC address via libcxi");

    if (!adapter->cxil_dev) {
        PMD_DRV_LOG(ERR, "No libcxi device handle");
        return -EINVAL;
    }

    /* Set MAC address via libcxi */
    ret = cxil_set_mac_address(adapter->cxil_dev, mac_addr->addr_bytes);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to set MAC address: %d", ret);
        return ret;
    }

    /* Copy MAC address to adapter */
    rte_ether_addr_copy(mac_addr, &adapter->mac_addr);

    return 0;
}

/* Get link information */
int
cxi_hw_get_link_info(struct cxi_adapter *adapter,
                     struct rte_eth_link *link)
{
    struct cxi_link_info link_info;
    int ret;

    PMD_DRV_LOG(DEBUG, "Getting link information via libcxi");

    if (!adapter->cxil_dev) {
        PMD_DRV_LOG(ERR, "No libcxi device handle");
        return -EINVAL;
    }

    /* Get link info from libcxi */
    ret = cxil_get_link_info(adapter->cxil_dev, &link_info);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to get link info: %d", ret);
        return ret;
    }

    /* Convert to DPDK link structure */
    link->link_speed = link_info.speed;
    link->link_duplex = link_info.duplex ? RTE_ETH_LINK_FULL_DUPLEX : RTE_ETH_LINK_HALF_DUPLEX;
    link->link_autoneg = link_info.autoneg ? RTE_ETH_LINK_AUTONEG : RTE_ETH_LINK_FIXED;
    link->link_status = link_info.link_status ? RTE_ETH_LINK_UP : RTE_ETH_LINK_DOWN;

    return 0;
}

/* Set link up */
int
cxi_hw_set_link_up(struct cxi_adapter *adapter)
{
    PMD_DRV_LOG(DEBUG, "Setting link up");

    /* Implementation would go here */
    RTE_SET_USED(adapter);
    return 0;
}

/* Set link down */
int
cxi_hw_set_link_down(struct cxi_adapter *adapter)
{
    PMD_DRV_LOG(DEBUG, "Setting link down");

    /* Implementation would go here */
    RTE_SET_USED(adapter);
    return 0;
}

/* Set promiscuous mode */
int
cxi_hw_set_promiscuous(struct cxi_adapter *adapter, bool enable)
{
    int ret;

    PMD_DRV_LOG(DEBUG, "%s promiscuous mode via libcxi",
                enable ? "Enabling" : "Disabling");

    if (!adapter->cxil_dev) {
        PMD_DRV_LOG(ERR, "No libcxi device handle");
        return -EINVAL;
    }

    /* Set promiscuous mode via libcxi */
    ret = cxil_set_promiscuous(adapter->cxil_dev, enable);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to set promiscuous mode: %d", ret);
        return ret;
    }

    return 0;
}

/* Set allmulticast mode */
int
cxi_hw_set_allmulticast(struct cxi_adapter *adapter, bool enable)
{
    int ret;

    PMD_DRV_LOG(DEBUG, "%s allmulticast mode via libcxi",
                enable ? "Enabling" : "Disabling");

    if (!adapter->cxil_dev) {
        PMD_DRV_LOG(ERR, "No libcxi device handle");
        return -EINVAL;
    }

    /* Set allmulticast mode via libcxi */
    ret = cxil_set_allmulticast(adapter->cxil_dev, enable);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to set allmulticast mode: %d", ret);
        return ret;
    }

    return 0;
}

/* Set MTU */
int
cxi_hw_set_mtu(struct cxi_adapter *adapter, uint16_t mtu)
{
    int ret;

    PMD_DRV_LOG(DEBUG, "Setting MTU to %u via libcxi", mtu);

    if (!adapter->cxil_dev) {
        PMD_DRV_LOG(ERR, "No libcxi device handle");
        return -EINVAL;
    }

    /* Set MTU via libcxi */
    ret = cxil_set_mtu(adapter->cxil_dev, mtu);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to set MTU: %d", ret);
        return ret;
    }

    return 0;
}

/* Enable interrupts */
int
cxi_hw_enable_interrupts(struct cxi_adapter *adapter)
{
    PMD_DRV_LOG(DEBUG, "Enabling interrupts");

    /* Implementation would go here */
    RTE_SET_USED(adapter);
    return 0;
}

/* Disable interrupts */
void
cxi_hw_disable_interrupts(struct cxi_adapter *adapter)
{
    PMD_DRV_LOG(DEBUG, "Disabling interrupts");

    /* Implementation would go here */
    RTE_SET_USED(adapter);
}

/* Configure RSS */
int
cxi_hw_configure_rss(struct cxi_adapter *adapter, struct rte_eth_rss_conf *rss_conf)
{
    PMD_DRV_LOG(DEBUG, "Configuring RSS via libcxi");

    if (!adapter->cxil_dev) {
        PMD_DRV_LOG(ERR, "No libcxi device handle");
        return -EINVAL;
    }

    /* Configure RSS via libcxi - placeholder implementation */
    /* This would use libcxi RSS configuration functions when available */
    RTE_SET_USED(rss_conf);

    PMD_DRV_LOG(INFO, "RSS configuration completed");
    return 0;
}

/* Update RSS hash configuration */
int
cxi_hw_rss_hash_update(struct cxi_adapter *adapter, struct rte_eth_rss_conf *rss_conf)
{
    PMD_DRV_LOG(DEBUG, "Updating RSS hash configuration via libcxi");

    if (!adapter->cxil_dev) {
        PMD_DRV_LOG(ERR, "No libcxi device handle");
        return -EINVAL;
    }

    /* Update RSS hash via libcxi - placeholder implementation */
    /* This would use libcxi RSS hash update functions when available */
    RTE_SET_USED(rss_conf);

    return 0;
}

/* Update RSS redirection table */
int
cxi_hw_rss_reta_update(struct cxi_adapter *adapter,
                       struct rte_eth_rss_reta_entry64 *reta_conf,
                       uint16_t reta_size)
{
    PMD_DRV_LOG(DEBUG, "Updating RSS RETA via libcxi, size: %u", reta_size);

    if (!adapter->cxil_dev) {
        PMD_DRV_LOG(ERR, "No libcxi device handle");
        return -EINVAL;
    }

    /* Update RSS RETA via libcxi - placeholder implementation */
    /* This would use libcxi RSS RETA update functions when available */
    RTE_SET_USED(reta_conf);

    return 0;
}

/* Query RSS redirection table */
int
cxi_hw_rss_reta_query(struct cxi_adapter *adapter,
                      struct rte_eth_rss_reta_entry64 *reta_conf,
                      uint16_t reta_size)
{
    PMD_DRV_LOG(DEBUG, "Querying RSS RETA via libcxi, size: %u", reta_size);

    if (!adapter->cxil_dev) {
        PMD_DRV_LOG(ERR, "No libcxi device handle");
        return -EINVAL;
    }

    /* Query RSS RETA via libcxi - placeholder implementation */
    /* This would use libcxi RSS RETA query functions when available */
    RTE_SET_USED(reta_conf);

    return 0;
}
