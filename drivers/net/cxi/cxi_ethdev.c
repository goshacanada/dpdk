/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Hewlett Packard Enterprise Development LP
 */

#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <rte_pci.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_dev.h>
#include <rte_log.h>

#include "cxi_ethdev.h"
#include "cxi_hw.h"

/* Logging */
int cxi_logtype_init;
int cxi_logtype_driver;

/* PCI device table */
static const struct rte_pci_id cxi_pci_id_map[] = {
    { RTE_PCI_DEVICE(CXI_VENDOR_ID, CXI_DEVICE_ID_C1) },
    { RTE_PCI_DEVICE(CXI_VENDOR_ID, CXI_DEVICE_ID_C2) },
    { .vendor_id = 0, /* sentinel */ },
};

/* Forward declarations */
static int cxi_dev_info_get(struct rte_eth_dev *dev,
                            struct rte_eth_dev_info *dev_info);
static int cxi_dev_configure(struct rte_eth_dev *dev);
static int cxi_dev_start(struct rte_eth_dev *dev);
static int cxi_dev_stop(struct rte_eth_dev *dev);
static int cxi_dev_close(struct rte_eth_dev *dev);
static int cxi_dev_reset(struct rte_eth_dev *dev);
static int cxi_stats_get(struct rte_eth_dev *dev,
                         struct rte_eth_stats *stats);
static int cxi_stats_reset(struct rte_eth_dev *dev);
static int cxi_link_update(struct rte_eth_dev *dev, int wait_to_complete);
static int cxi_promiscuous_enable(struct rte_eth_dev *dev);
static int cxi_promiscuous_disable(struct rte_eth_dev *dev);
static int cxi_allmulticast_enable(struct rte_eth_dev *dev);
static int cxi_allmulticast_disable(struct rte_eth_dev *dev);
static int cxi_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);

/* Device operations structure */
static const struct eth_dev_ops cxi_eth_dev_ops = {
    .dev_configure        = cxi_dev_configure,
    .dev_start            = cxi_dev_start,
    .dev_stop             = cxi_dev_stop,
    .dev_close            = cxi_dev_close,
    .dev_reset            = cxi_dev_reset,
    .dev_infos_get        = cxi_dev_info_get,
    .rx_queue_setup       = cxi_rx_queue_setup,
    .tx_queue_setup       = cxi_tx_queue_setup,
    .rx_queue_release     = cxi_rx_queue_release,
    .tx_queue_release     = cxi_tx_queue_release,
    .link_update          = cxi_link_update,
    .stats_get            = cxi_stats_get,
    .stats_reset          = cxi_stats_reset,
    .promiscuous_enable   = cxi_promiscuous_enable,
    .promiscuous_disable  = cxi_promiscuous_disable,
    .allmulticast_enable  = cxi_allmulticast_enable,
    .allmulticast_disable = cxi_allmulticast_disable,
    .mtu_set              = cxi_mtu_set,
    .rss_hash_update      = cxi_rss_hash_update,
    .rss_hash_conf_get    = cxi_rss_hash_conf_get,
    .reta_update          = cxi_rss_reta_update,
    .reta_query           = cxi_rss_reta_query,
};

static int
cxi_dev_info_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    struct cxi_hw_caps caps;
    int ret;

    PMD_DRV_LOG(DEBUG, "Getting device info");

    ret = cxi_hw_get_capabilities(adapter, &caps);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to get hardware capabilities");
        return ret;
    }

    dev_info->driver_name = dev->device->driver->name;
    dev_info->if_index = 0;
    dev_info->min_mtu = caps.min_mtu;
    dev_info->max_mtu = caps.max_mtu;
    dev_info->min_rx_bufsize = CXI_MIN_PKT_SIZE;
    dev_info->max_rx_pktlen = caps.max_mtu;
    dev_info->max_rx_queues = CXI_MAX_RX_QUEUES;
    dev_info->max_tx_queues = CXI_MAX_TX_QUEUES;
    dev_info->max_mac_addrs = 1;

    /* RX offload capabilities */
    dev_info->rx_offload_capa = RTE_ETH_RX_OFFLOAD_CHECKSUM;
    if (caps.supports_vlan)
        dev_info->rx_offload_capa |= RTE_ETH_RX_OFFLOAD_VLAN_STRIP;

    /* TX offload capabilities */
    dev_info->tx_offload_capa = RTE_ETH_TX_OFFLOAD_CHECKSUM;
    if (caps.supports_tso)
        dev_info->tx_offload_capa |= RTE_ETH_TX_OFFLOAD_TCP_TSO;
    if (caps.supports_vlan)
        dev_info->tx_offload_capa |= RTE_ETH_TX_OFFLOAD_VLAN_INSERT;

    /* Queue offload capabilities */
    dev_info->rx_queue_offload_capa = dev_info->rx_offload_capa;
    dev_info->tx_queue_offload_capa = dev_info->tx_offload_capa;

    /* Descriptor limits */
    dev_info->rx_desc_lim.nb_max = CXI_MAX_QUEUE_SIZE;
    dev_info->rx_desc_lim.nb_min = CXI_MIN_QUEUE_SIZE;
    dev_info->rx_desc_lim.nb_align = 1;
    dev_info->tx_desc_lim.nb_max = CXI_MAX_QUEUE_SIZE;
    dev_info->tx_desc_lim.nb_min = CXI_MIN_QUEUE_SIZE;
    dev_info->tx_desc_lim.nb_align = 1;

    /* RSS capabilities */
    if (caps.supports_rss) {
        dev_info->reta_size = CXI_ETH_MAX_INDIR_ENTRIES;
        dev_info->hash_key_size = CXI_ETH_HASH_KEY_SIZE;
        dev_info->flow_type_rss_offloads = CXI_RSS_OFFLOAD_ALL;
    }

    /* Default configuration */
    dev_info->default_rxconf.rx_free_thresh = 32;
    dev_info->default_txconf.tx_free_thresh = 32;

    return 0;
}

static int
cxi_dev_configure(struct rte_eth_dev *dev)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    struct rte_eth_conf *conf = &dev->data->dev_conf;

    PMD_DRV_LOG(INFO, "Configuring device with %u RX queues, %u TX queues",
                dev->data->nb_rx_queues, dev->data->nb_tx_queues);

    /* Validate configuration */
    if (dev->data->nb_rx_queues > CXI_MAX_RX_QUEUES) {
        PMD_DRV_LOG(ERR, "Too many RX queues: %u (max: %u)",
                    dev->data->nb_rx_queues, CXI_MAX_RX_QUEUES);
        return -EINVAL;
    }

    if (dev->data->nb_tx_queues > CXI_MAX_TX_QUEUES) {
        PMD_DRV_LOG(ERR, "Too many TX queues: %u (max: %u)",
                    dev->data->nb_tx_queues, CXI_MAX_TX_QUEUES);
        return -EINVAL;
    }

    /* Store configuration */
    adapter->num_rx_queues = dev->data->nb_rx_queues;
    adapter->num_tx_queues = dev->data->nb_tx_queues;

    /* Configure multi-queue modes */
    if (conf->rxmode.mq_mode & RTE_ETH_MQ_RX_RSS) {
        PMD_DRV_LOG(INFO, "RSS mode requested");
        ret = cxi_hw_configure_rss(adapter, &conf->rx_adv_conf.rss_conf);
        if (ret) {
            PMD_DRV_LOG(ERR, "Failed to configure RSS: %d", ret);
            return ret;
        }
        adapter->rss_enabled = true;
    } else {
        adapter->rss_enabled = false;
    }

    /* Configure TX multi-queue mode */
    if (conf->txmode.mq_mode & RTE_ETH_MQ_TX_NONE) {
        /* Simple round-robin or single queue mode */
        adapter->tx_mq_mode = CXI_MQ_MODE_NONE;
    } else {
        /* Future: support for other TX MQ modes */
        adapter->tx_mq_mode = CXI_MQ_MODE_NONE;
    }

    return 0;
}

static int
cxi_dev_start(struct rte_eth_dev *dev)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    int ret;

    PMD_DRV_LOG(INFO, "Starting device");

    /* Initialize hardware */
    ret = cxi_hw_init_device(adapter);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to initialize hardware: %d", ret);
        return ret;
    }

    /* Start all configured queues */
    for (uint16_t i = 0; i < adapter->num_rx_queues; i++) {
        if (adapter->rx_queues[i]) {
            ret = cxi_hw_cq_start(adapter, &adapter->rx_queues[i]->cq);
            if (ret) {
                PMD_DRV_LOG(ERR, "Failed to start RX queue %u", i);
                goto start_error;
            }
            ret = cxi_hw_eq_start(adapter, &adapter->rx_queues[i]->eq);
            if (ret) {
                PMD_DRV_LOG(ERR, "Failed to start RX EQ %u", i);
                goto start_error;
            }
            adapter->rx_queues[i]->started = true;
        }
    }

    for (uint16_t i = 0; i < adapter->num_tx_queues; i++) {
        if (adapter->tx_queues[i]) {
            ret = cxi_hw_cq_start(adapter, &adapter->tx_queues[i]->cq);
            if (ret) {
                PMD_DRV_LOG(ERR, "Failed to start TX queue %u", i);
                goto start_error;
            }
            ret = cxi_hw_eq_start(adapter, &adapter->tx_queues[i]->eq);
            if (ret) {
                PMD_DRV_LOG(ERR, "Failed to start TX EQ %u", i);
                goto start_error;
            }
            adapter->tx_queues[i]->started = true;
        }
    }

    /* Enable interrupts */
    ret = cxi_hw_enable_interrupts(adapter);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to enable interrupts");
        goto start_error;
    }

    /* Set link up */
    ret = cxi_hw_set_link_up(adapter);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to set link up");
        goto start_error;
    }

    adapter->started = true;
    PMD_DRV_LOG(INFO, "Device started successfully");
    return 0;

start_error:
    cxi_dev_stop(dev);
    return ret;
}

static int
cxi_dev_stop(struct rte_eth_dev *dev)
{
    struct cxi_adapter *adapter = dev->data->dev_private;

    PMD_DRV_LOG(INFO, "Stopping device");

    if (!adapter->started)
        return 0;

    /* Disable interrupts */
    cxi_hw_disable_interrupts(adapter);

    /* Stop all queues */
    for (uint16_t i = 0; i < adapter->num_rx_queues; i++) {
        if (adapter->rx_queues[i] && adapter->rx_queues[i]->started) {
            cxi_hw_cq_stop(adapter, &adapter->rx_queues[i]->cq);
            cxi_hw_eq_stop(adapter, &adapter->rx_queues[i]->eq);
            adapter->rx_queues[i]->started = false;
        }
    }

    for (uint16_t i = 0; i < adapter->num_tx_queues; i++) {
        if (adapter->tx_queues[i] && adapter->tx_queues[i]->started) {
            cxi_hw_cq_stop(adapter, &adapter->tx_queues[i]->cq);
            cxi_hw_eq_stop(adapter, &adapter->tx_queues[i]->eq);
            adapter->tx_queues[i]->started = false;
        }
    }

    /* Set link down */
    cxi_hw_set_link_down(adapter);

    adapter->started = false;
    PMD_DRV_LOG(INFO, "Device stopped");
    return 0;
}

static int
cxi_dev_close(struct rte_eth_dev *dev)
{
    struct cxi_adapter *adapter = dev->data->dev_private;

    PMD_DRV_LOG(INFO, "Closing device");

    if (rte_eal_process_type() != RTE_PROC_PRIMARY)
        return 0;

    cxi_dev_stop(dev);

    /* Free all queues */
    for (uint16_t i = 0; i < adapter->num_rx_queues; i++) {
        if (adapter->rx_queues[i]) {
            cxi_rx_queue_release(dev, i);
        }
    }

    for (uint16_t i = 0; i < adapter->num_tx_queues; i++) {
        if (adapter->tx_queues[i]) {
            cxi_tx_queue_release(dev, i);
        }
    }

    /* Cleanup hardware */
    cxi_hw_cleanup_device(adapter);

    PMD_DRV_LOG(INFO, "Device closed");
    return 0;
}

static int
cxi_dev_reset(struct rte_eth_dev *dev)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    int ret;

    PMD_DRV_LOG(INFO, "Resetting device");

    ret = cxi_dev_stop(dev);
    if (ret)
        return ret;

    ret = cxi_hw_reset_device(adapter);
    if (ret) {
        PMD_DRV_LOG(ERR, "Hardware reset failed");
        return ret;
    }

    return cxi_dev_start(dev);
}

/* RSS hash configuration update */
int
cxi_rss_hash_update(struct rte_eth_dev *dev, struct rte_eth_rss_conf *rss_conf)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    int ret;

    PMD_DRV_LOG(DEBUG, "Updating RSS hash configuration");

    if (!adapter->rss_enabled) {
        PMD_DRV_LOG(ERR, "RSS not enabled");
        return -ENOTSUP;
    }

    ret = cxi_hw_rss_hash_update(adapter, rss_conf);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to update RSS hash: %d", ret);
        return ret;
    }

    /* Update local configuration */
    if (rss_conf->rss_key && rss_conf->rss_key_len <= CXI_ETH_HASH_KEY_SIZE) {
        memcpy(adapter->rss_conf.rss_key, rss_conf->rss_key, rss_conf->rss_key_len);
        adapter->rss_conf.rss_key_len = rss_conf->rss_key_len;
    }
    adapter->rss_conf.rss_hf = rss_conf->rss_hf;

    return 0;
}

/* RSS hash configuration get */
int
cxi_rss_hash_conf_get(struct rte_eth_dev *dev, struct rte_eth_rss_conf *rss_conf)
{
    struct cxi_adapter *adapter = dev->data->dev_private;

    PMD_DRV_LOG(DEBUG, "Getting RSS hash configuration");

    if (!adapter->rss_enabled) {
        PMD_DRV_LOG(ERR, "RSS not enabled");
        return -ENOTSUP;
    }

    if (rss_conf->rss_key && rss_conf->rss_key_len >= adapter->rss_conf.rss_key_len) {
        memcpy(rss_conf->rss_key, adapter->rss_conf.rss_key,
               adapter->rss_conf.rss_key_len);
    }
    rss_conf->rss_key_len = adapter->rss_conf.rss_key_len;
    rss_conf->rss_hf = adapter->rss_conf.rss_hf;

    return 0;
}

/* RSS redirection table update */
int
cxi_rss_reta_update(struct rte_eth_dev *dev,
                    struct rte_eth_rss_reta_entry64 *reta_conf,
                    uint16_t reta_size)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    int ret;

    PMD_DRV_LOG(DEBUG, "Updating RSS RETA, size: %u", reta_size);

    if (!adapter->rss_enabled) {
        PMD_DRV_LOG(ERR, "RSS not enabled");
        return -ENOTSUP;
    }

    if (reta_size > CXI_ETH_MAX_INDIR_ENTRIES) {
        PMD_DRV_LOG(ERR, "RETA size too large: %u (max: %u)",
                    reta_size, CXI_ETH_MAX_INDIR_ENTRIES);
        return -EINVAL;
    }

    ret = cxi_hw_rss_reta_update(adapter, reta_conf, reta_size);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to update RSS RETA: %d", ret);
        return ret;
    }

    /* Update local RETA configuration */
    for (uint16_t i = 0; i < reta_size; i++) {
        uint16_t idx = i / RTE_ETH_RETA_GROUP_SIZE;
        uint16_t shift = i % RTE_ETH_RETA_GROUP_SIZE;
        if (reta_conf[idx].mask & (1ULL << shift)) {
            adapter->rss_conf.reta[i] = reta_conf[idx].reta[shift];
        }
    }

    return 0;
}

/* RSS redirection table query */
int
cxi_rss_reta_query(struct rte_eth_dev *dev,
                   struct rte_eth_rss_reta_entry64 *reta_conf,
                   uint16_t reta_size)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    int ret;

    PMD_DRV_LOG(DEBUG, "Querying RSS RETA, size: %u", reta_size);

    if (!adapter->rss_enabled) {
        PMD_DRV_LOG(ERR, "RSS not enabled");
        return -ENOTSUP;
    }

    if (reta_size > CXI_ETH_MAX_INDIR_ENTRIES) {
        PMD_DRV_LOG(ERR, "RETA size too large: %u (max: %u)",
                    reta_size, CXI_ETH_MAX_INDIR_ENTRIES);
        return -EINVAL;
    }

    ret = cxi_hw_rss_reta_query(adapter, reta_conf, reta_size);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to query RSS RETA: %d", ret);
        return ret;
    }

    /* Fill in the RETA configuration from local cache */
    for (uint16_t i = 0; i < reta_size; i++) {
        uint16_t idx = i / RTE_ETH_RETA_GROUP_SIZE;
        uint16_t shift = i % RTE_ETH_RETA_GROUP_SIZE;
        if (reta_conf[idx].mask & (1ULL << shift)) {
            reta_conf[idx].reta[shift] = adapter->rss_conf.reta[i];
        }
    }

    return 0;
}

static int
cxi_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    struct cxi_hw_stats hw_stats;
    int ret;

    ret = cxi_hw_get_stats(adapter, &hw_stats);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to get hardware statistics");
        return ret;
    }

    /* Map hardware stats to DPDK stats */
    stats->ipackets = hw_stats.rx_packets;
    stats->ibytes = hw_stats.rx_bytes;
    stats->ierrors = hw_stats.rx_errors;
    stats->imissed = hw_stats.rx_dropped;

    stats->opackets = hw_stats.tx_packets;
    stats->obytes = hw_stats.tx_bytes;
    stats->oerrors = hw_stats.tx_errors;

    return 0;
}

static int
cxi_stats_reset(struct rte_eth_dev *dev)
{
    struct cxi_adapter *adapter = dev->data->dev_private;

    cxi_hw_clear_stats(adapter);
    memset(&adapter->stats, 0, sizeof(adapter->stats));

    return 0;
}

static int
cxi_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    struct rte_eth_link link;
    int ret;

    RTE_SET_USED(wait_to_complete);

    ret = cxi_hw_get_link_info(adapter, &link);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to get link info");
        return ret;
    }

    return rte_eth_linkstatus_set(dev, &link);
}

static int
cxi_promiscuous_enable(struct rte_eth_dev *dev)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    int ret;

    ret = cxi_hw_set_promiscuous(adapter, true);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to enable promiscuous mode");
        return ret;
    }

    adapter->promiscuous = true;
    return 0;
}

static int
cxi_promiscuous_disable(struct rte_eth_dev *dev)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    int ret;

    ret = cxi_hw_set_promiscuous(adapter, false);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to disable promiscuous mode");
        return ret;
    }

    adapter->promiscuous = false;
    return 0;
}

static int
cxi_allmulticast_enable(struct rte_eth_dev *dev)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    int ret;

    ret = cxi_hw_set_allmulticast(adapter, true);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to enable allmulticast mode");
        return ret;
    }

    adapter->allmulticast = true;
    return 0;
}

static int
cxi_allmulticast_disable(struct rte_eth_dev *dev)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    int ret;

    ret = cxi_hw_set_allmulticast(adapter, false);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to disable allmulticast mode");
        return ret;
    }

    adapter->allmulticast = false;
    return 0;
}

static int
cxi_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
    struct cxi_adapter *adapter = dev->data->dev_private;
    int ret;

    ret = cxi_hw_set_mtu(adapter, mtu);
    if (ret) {
        PMD_DRV_LOG(ERR, "Failed to set MTU to %u", mtu);
        return ret;
    }

    adapter->max_rx_pkt_len = mtu + RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;
    return 0;
}

static int
cxi_eth_dev_init(struct rte_eth_dev *eth_dev)
{
    struct cxi_adapter *adapter;
    struct rte_pci_device *pci_dev;
    int ret;

    PMD_INIT_LOG(DEBUG, "Initializing CXI device");

    eth_dev->dev_ops = &cxi_eth_dev_ops;
    eth_dev->rx_pkt_burst = cxi_recv_pkts;
    eth_dev->tx_pkt_burst = cxi_xmit_pkts;

    if (rte_eal_process_type() != RTE_PROC_PRIMARY)
        return 0;

    pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

    /* Allocate adapter structure */
    adapter = rte_zmalloc("cxi_adapter", sizeof(*adapter), 0);
    if (!adapter) {
        PMD_INIT_LOG(ERR, "Failed to allocate adapter structure");
        return -ENOMEM;
    }

    adapter->eth_dev = eth_dev;
    adapter->pci_dev = pci_dev;
    eth_dev->data->dev_private = adapter;

    /* Initialize hardware info */
    adapter->hw_info.vendor_id = pci_dev->id.vendor_id;
    adapter->hw_info.device_id = pci_dev->id.device_id;
    adapter->hw_info.subsystem_vendor_id = pci_dev->id.subsystem_vendor_id;
    adapter->hw_info.subsystem_device_id = pci_dev->id.subsystem_device_id;
    adapter->hw_info.revision = pci_dev->id.class_id;
    adapter->hw_info.is_cassini_2 = (pci_dev->id.device_id == CXI_DEVICE_ID_C2);

    /* Map PCI resources */
    ret = rte_pci_map_device(pci_dev);
    if (ret) {
        PMD_INIT_LOG(ERR, "Failed to map PCI device");
        goto init_error;
    }

    /* Open libcxi device */
    ret = cxil_open_device(pci_dev->addr.devid, &adapter->cxil_dev);
    if (ret) {
        PMD_INIT_LOG(ERR, "Failed to open libcxi device: %d", ret);
        goto init_error;
    }

    /* Allocate LNI - following cxi_udp_gen.c pattern */
    ret = cxil_alloc_lni(adapter->cxil_dev, &adapter->lni, CXI_DEFAULT_SVC_ID);
    if (ret) {
        PMD_INIT_LOG(ERR, "Failed to allocate LNI: %d", ret);
        goto init_error;
    }

    /* Allocate Communication Profile - CRITICAL for ethernet like cxi_udp_gen.c */
    ret = cxil_alloc_cp(adapter->lni, 0, CXI_TC_ETH, CXI_TC_TYPE_DEFAULT, &adapter->cp);
    if (ret) {
        PMD_INIT_LOG(ERR, "Failed to allocate Communication Profile: %d", ret);
        goto init_error;
    }

    /* Initialize spinlock */
    rte_spinlock_init(&adapter->lock);

    /* Allocate MAC address array */
    eth_dev->data->mac_addrs = rte_zmalloc("cxi_mac_addrs",
                                          sizeof(struct rte_ether_addr), 0);
    if (!eth_dev->data->mac_addrs) {
        PMD_INIT_LOG(ERR, "Failed to allocate MAC address array");
        ret = -ENOMEM;
        goto init_error;
    }

    /* Probe hardware */
    ret = cxi_hw_probe(pci_dev);
    if (ret) {
        PMD_INIT_LOG(ERR, "Hardware probe failed");
        goto init_error;
    }

    /* Get MAC address */
    ret = cxi_hw_get_mac_addr(adapter, &adapter->mac_addr);
    if (ret) {
        PMD_INIT_LOG(ERR, "Failed to get MAC address");
        goto init_error;
    }

    /* Copy MAC address to device data */
    rte_ether_addr_copy(&adapter->mac_addr, &eth_dev->data->mac_addrs[0]);

    PMD_INIT_LOG(INFO, "CXI device initialized successfully");
    PMD_INIT_LOG(INFO, "MAC address: " RTE_ETHER_ADDR_PRT_FMT,
                 RTE_ETHER_ADDR_BYTES(&adapter->mac_addr));

    return 0;

init_error:
    if (eth_dev->data->mac_addrs) {
        rte_free(eth_dev->data->mac_addrs);
        eth_dev->data->mac_addrs = NULL;
    }
    if (adapter->cp) {
        cxil_destroy_cp(adapter->cp);
        adapter->cp = NULL;
    }
    if (adapter->lni) {
        cxil_destroy_lni(adapter->lni);
        adapter->lni = NULL;
    }
    if (adapter->cxil_dev) {
        cxil_close_device(adapter->cxil_dev);
        adapter->cxil_dev = NULL;
    }
    rte_free(adapter);
    return ret;
}

static int
cxi_eth_dev_uninit(struct rte_eth_dev *eth_dev)
{
    struct cxi_adapter *adapter = eth_dev->data->dev_private;

    PMD_INIT_LOG(DEBUG, "Uninitializing CXI device");

    if (rte_eal_process_type() != RTE_PROC_PRIMARY)
        return 0;

    cxi_dev_close(eth_dev);

    /* Cleanup libcxi resources in reverse order */
    if (adapter->cp) {
        cxil_destroy_cp(adapter->cp);
        adapter->cp = NULL;
    }
    if (adapter->lni) {
        cxil_destroy_lni(adapter->lni);
        adapter->lni = NULL;
    }
    if (adapter->cxil_dev) {
        cxil_close_device(adapter->cxil_dev);
        adapter->cxil_dev = NULL;
    }

    /* Free MAC address array */
    if (eth_dev->data->mac_addrs) {
        rte_free(eth_dev->data->mac_addrs);
        eth_dev->data->mac_addrs = NULL;
    }

    /* Unmap PCI device */
    rte_pci_unmap_device(RTE_ETH_DEV_TO_PCI(eth_dev));

    /* Free adapter */
    rte_free(adapter);
    eth_dev->data->dev_private = NULL;

    return 0;
}

static int
cxi_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
              struct rte_pci_device *pci_dev)
{
    return rte_eth_dev_pci_generic_probe(pci_dev, sizeof(struct cxi_adapter),
                                        cxi_eth_dev_init);
}

static int
cxi_pci_remove(struct rte_pci_device *pci_dev)
{
    return rte_eth_dev_pci_generic_remove(pci_dev, cxi_eth_dev_uninit);
}

static struct rte_pci_driver cxi_pmd = {
    .id_table = cxi_pci_id_map,
    .drv_flags = RTE_PCI_DRV_NEED_MAPPING,
    .probe = cxi_pci_probe,
    .remove = cxi_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_cxi, cxi_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_cxi, cxi_pci_id_map);
RTE_PMD_REGISTER_KMOD_DEP(net_cxi, "* igb_uio | uio_pci_generic | vfio-pci");

RTE_LOG_REGISTER_SUFFIX(cxi_logtype_init, init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(cxi_logtype_driver, driver, NOTICE);
