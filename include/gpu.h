#ifndef GPU_H
#define GPU_H

#include <stdint.h>

#define GPU_PDE_VALID_BIT 0
#define GPU_PDE_IS_PTE_BIT 54
#define GPU_PDE_TF_BIT 56
#define GPU_PDE_BLOCK_FRAG_BIT 59
#define GPU_PDE_ADDR_MASK 0x0000FFFFFFFFFFC0ULL

#define PROT_GPU_READ 0x10
#define PROT_GPU_WRITE 0x20
#define MAP_NO_COALESCE 0x00400000

#define GPU_SUBMIT_IOCTL 0xC0108102

#define PM4_TYPE3 3
#define PM4_SHADER_COMPUTE 1
#define PM4_OPCODE_DMA_DATA 0x50
#define PM4_OPCODE_INDIRECT_BUF 0x3F

struct gpu_kernel_offsets {
  uint64_t proc_vmspace;
  uint64_t vmspace_vm_vmid;
  uint64_t data_base_gvmspace;
  uint64_t sizeof_gvmspace;
  uint64_t gvmspace_page_dir_va;
  uint64_t gvmspace_size;
  uint64_t gvmspace_start_va;
};

struct gpu_ctx {
  int fd;
  int initialized;

  uint64_t victim_va;
  uint64_t transfer_va;
  uint64_t cmd_va;

  uint64_t victim_real_pa;
  uint64_t victim_ptbe_va;
  uint64_t cleared_ptbe;
  uint64_t page_size;
  uint64_t dmem_size;
};

void gpu_set_offsets(struct gpu_kernel_offsets *offsets);

int gpu_init(void);
int gpu_init_internal(void);

int gpu_test(void);

int gpu_read_phys(uint64_t phys_addr, void *out_buf, uint32_t size);
uint8_t gpu_read_phys1(uint64_t phys_addr);
uint32_t gpu_read_phys4(uint64_t phys_addr);
uint64_t gpu_read_phys8(uint64_t phys_addr);

int gpu_write_phys(uint64_t phys_addr, const void *in_buf, uint32_t size);
void gpu_write_phys4(uint64_t phys_addr, uint32_t value);
void gpu_write_phys8(uint64_t phys_addr, uint64_t value);

void gpu_cleanup(void);

struct gpu_ctx *gpu_get_ctx(void);

#endif
