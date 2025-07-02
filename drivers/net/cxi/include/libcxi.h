/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Copyright 2020,2024 Hewlett Packard Enterprise Development LP */
#ifndef __LIBCXI_H__
#define __LIBCXI_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CXIL_API __attribute__((visibility("default")))

#ifndef __user
#define __user
#endif

#include "cxi_prov_hw.h"
#include "cassini_user_defs.h"

#define CXIL_DEVNAME_MAX 13 /* "cxi" + up to 10 digits */
#define CXIL_DRVNAME_MAX 8
#define CXIL_FRUDESC_MAX 16

struct cxil_devinfo {
    unsigned int dev_id;
    union {
        unsigned int nic_addr; /* obsolete */
        unsigned int nid;
    };
    unsigned int pid_bits;
    unsigned int pid_count;
    unsigned int pid_granule;
    unsigned int min_free_shift;
    unsigned int rdzv_get_idx;
    char device_name[CXIL_DEVNAME_MAX+1];
    char driver_name[CXIL_DRVNAME_MAX+1];
    unsigned int vendor_id;
    unsigned int device_id;
    unsigned int device_rev;
    unsigned int device_proto;
    unsigned int device_platform;
    uint16_t num_ptes;
    uint16_t num_txqs;
    uint16_t num_tgqs;
    uint16_t num_eqs;
    uint16_t num_cts;
    uint16_t num_acs;
    uint16_t num_tles;
    uint16_t num_les;
    uint16_t pci_domain;
    uint8_t pci_bus;
    uint8_t pci_device;
    uint8_t pci_function;
    size_t link_mtu;
    size_t link_speed;
    uint8_t link_state;
    int uc_nic;
    unsigned int pct_eq;
    /* Cassini version (CASSINI_1_0, ...) */
    enum cassini_version cassini_version;
    /* type of board: "Brazos", ... */
    char fru_description[CXIL_FRUDESC_MAX];
    bool is_vf; /* PCIe PF or VF */
    /* System info (mix or homogeneous) */
    enum system_type_identifier system_type_identifier;
};

struct cxil_pte {
    unsigned int ptn;
};

struct cxil_domain {
    unsigned int vni;
    unsigned int pid;
};

struct cxil_dev {
    struct cxil_devinfo info;
};

struct cxil_lni {
    unsigned int id;
};

struct cxil_pte;
struct cxil_pte_map;
struct cxil_wait_obj;

struct cxil_device_list {
    unsigned int count;
    struct cxil_devinfo info[];
};

struct cxil_svc_list {
    unsigned int count;
    struct cxi_svc_desc descs[];
};

struct cxil_svc_rsrc_list {
    unsigned int count;
    struct cxi_rsrc_use rsrcs[];
};

/**
 * @brief Tests if the CXI retry handler is running for a device.
 *
 * @param devinfo Device info for the device to test
 *
 * @return True is returned if a retry handler is running for the device.
 */
static inline bool cxil_rh_running(struct cxil_devinfo *devinfo) {
    return devinfo->pct_eq != C_EQ_NONE;
}

/* Function declarations for libcxi API */
CXIL_API int cxil_get_device_list(struct cxil_device_list **dev_list);
CXIL_API void cxil_free_device_list(struct cxil_device_list *dev_list);
CXIL_API int cxil_open_device(uint32_t dev_id, struct cxil_dev **dev);
CXIL_API void cxil_close_device(struct cxil_dev *dev);
CXIL_API int cxil_alloc_lni(struct cxil_dev *dev, struct cxil_lni **lni, unsigned int svc_id);
CXIL_API int cxil_destroy_lni(struct cxil_lni *lni);
CXIL_API int cxil_alloc_cp(struct cxil_lni *lni, unsigned int vni, enum cxi_traffic_class tc, enum cxi_traffic_class_type tc_type, struct cxi_cp **cp);
CXIL_API int cxil_destroy_cp(struct cxi_cp *cp);
CXIL_API int cxil_alloc_domain(struct cxil_lni *lni, unsigned int vni, unsigned int pid, struct cxil_domain **domain);
CXIL_API int cxil_destroy_domain(struct cxil_domain *domain);
CXIL_API int cxil_alloc_cmdq(struct cxil_lni *lni, struct cxi_eq *evtq, const struct cxi_cq_alloc_opts *opts, struct cxi_cq **cmdq);
CXIL_API int cxil_destroy_cmdq(struct cxi_cq *cmdq);
CXIL_API int cxil_map(struct cxil_lni *lni, void *va, size_t len, uint32_t flags, struct cxi_md_hints *hints, struct cxi_md **md);
CXIL_API int cxil_unmap(struct cxi_md *md);
CXIL_API int cxil_alloc_evtq(struct cxil_lni *lni, const struct cxi_md *md, const struct cxi_eq_attr *attr, struct cxil_wait_obj *event_wait, struct cxil_wait_obj *status_wait, struct cxi_eq **evtq);

/* Ethernet-specific functions */
CXIL_API int cxil_init_eth_device(struct cxil_dev *dev);
CXIL_API int cxil_get_eth_capabilities(struct cxil_dev *dev, struct cxi_eth_caps *caps);
CXIL_API int cxil_get_mac_address(struct cxil_dev *dev, uint8_t *mac_addr);
CXIL_API int cxil_set_mac_address(struct cxil_dev *dev, const uint8_t *mac_addr);
CXIL_API int cxil_get_link_info(struct cxil_dev *dev, struct cxi_link_info *link_info);
CXIL_API int cxil_set_promiscuous(struct cxil_dev *dev, bool enable);
CXIL_API int cxil_set_allmulticast(struct cxil_dev *dev, bool enable);
CXIL_API int cxil_set_mtu(struct cxil_dev *dev, uint32_t mtu);

/* Command queue functions */
CXIL_API int cxi_cq_emit_c_state(struct cxi_cq *cq, const struct c_cstate_cmd *cmd);
CXIL_API int cxil_destroy_evtq(struct cxi_eq *evtq);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __LIBCXI_H__ */
