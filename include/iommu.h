#ifndef IOMMU_H
#define IOMMU_H

#include <stdint.h>

#define IOMMU_MMIO_CB_HEAD 0xa000
#define IOMMU_MMIO_CB_TAIL 0xa008

#define IOMMU_CB_SIZE 0x2000
#define IOMMU_CB_MASK (IOMMU_CB_SIZE - 1)
#define IOMMU_CMD_ENTRY_SIZE 0x10

#define IOMMU_SC_MMIO_VA 0x40
#define IOMMU_SC_CB2_PTR 0x78
#define IOMMU_SC_CB3_PTR 0x80
#define IOMMU_SC_EB_PTR 0x60b90

typedef struct _iommu_ctx {
  uint64_t cb2_base;
  uint64_t cb3_base;
  uint64_t eb_base;
  uint64_t mmio_va;
} iommu_ctx;

extern iommu_ctx iommu_store;
extern iommu_ctx *iommu;

int iommu_init(void);

void iommu_submit_cmd(const void *cmd);

void iommu_write8_pa(uint64_t pa, uint64_t val);

void iommu_write4_pa(uint64_t pa, uint32_t val);

void iommu_write_pa(uint64_t pa, const void *data, uint32_t len);

#endif
