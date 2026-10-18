#include "boot_linux.h"
#include "../include/config.h"
#include "../include/linux.h"
#include "../shellcode_hv/shellcode_hv.h"
#include "utils.h"

#define DIG1TRANSMITTERCONTROL 0x4c

#define TRANSMITTER_CONTROL_ENABLE 1
#define TRANSMITTER_CONTROL_SET_VOLTAGE_AND_PREEMPASIS 11

int (*transmitter_control)(int cmd, void *control) = NULL;
int (*mp3_initialize)(int vmid) = NULL;
int (*mp3_invoke)(int cmd_id, void *req, void *rsp) = NULL;

uint64_t g_vbios;

uint64_t g_step;
uint64_t g_rc_transmitter, g_rc_voltage, g_rc_mp3_init, g_rc_mp3_hdcp, g_rc_mp3_output;

uint64_t g_dp_vspe_raw = 0xFF, g_dp_vswing, g_dp_preemph;

typedef struct {
  uint64_t flags;
  uint64_t addr;
  uint64_t size;
} __attribute__((packed)) SceSblHvShmTmrPtState;

typedef uint64_t SceSblHvShmTmrIdBmp;
typedef uint16_t SceSblHvShmTmrPtIdBmp;

typedef struct {
  uint32_t sig;
  uint32_t ver;
  SceSblHvShmTmrPtIdBmp tmrMapPts[64];
  SceSblHvShmTmrIdBmp tmrOvlpIds[64];
  SceSblHvShmTmrPtState tmrPtStates[64];
  uint32_t nmiCounts[16];
  uint8_t reserved[64];
} __attribute__((packed)) SceSblHvShm;

typedef struct {
  uint8_t lanenum;
  uint32_t rate;
  uint32_t pad;
  uint32_t lane_setting_1;
  uint32_t lane_setting_2;
} transmitter_args;

struct dig_transmitter_control_parameters_v1_6 {
  uint8_t phyid;
  uint8_t action;
  union {
    uint8_t digmode;
    uint8_t dplaneset;
  } mode_laneset;
  uint8_t lanenum;
  uint32_t symclk_10khz;
  uint8_t hpdsel;
  uint8_t digfe_sel;
  uint8_t connobj_id;
  uint8_t reserved;
  uint32_t reserved1;
};

static struct linux_info info;

static int mp3_req[1281], mp3_rsp[1282];

static inline void stac(void) { __asm__ volatile("stac" : : : "cc"); }

static inline void clac(void) { __asm__ volatile("clac" : : : "cc"); }

static inline uint64_t vmmcall(uint64_t nr, uint64_t a0, uint64_t a1,
                               uint64_t a2) {
  uint64_t ret;
  __asm__ volatile("vmmcall"
                   : "=a"(ret)
                   : "a"(nr), "b"(a0), "c"(a1), "d"(a2)
                   : "memory");
  return ret;
}

static uint64_t get_hv_shm(void) {
  if (args.fw_version >= 0x0500 && args.fw_version < 0x0600) {
    return 0x62a01000;
  } else if (args.fw_version >= 0x0600 && args.fw_version < 0x0800) {
    return 0x62a22000;
  }
  return -1;
}

static int dp_enable_link_phy(int lanenum, int linkrate) {
  struct dig_transmitter_control_parameters_v1_6 params = {};
  params.phyid = 0;
  params.action = TRANSMITTER_CONTROL_ENABLE;
  params.mode_laneset.digmode = 0;
  params.lanenum = lanenum;
  params.symclk_10khz = 27000 * linkrate / 10;
  params.hpdsel = 0;
  params.digfe_sel = 0;
  params.connobj_id = 0;

  if (!transmitter_control) return -0x5101;
  return transmitter_control(DIG1TRANSMITTERCONTROL, &params);
}

#define PRESLIDE_DP_VSPE   0x2D5834EULL

#ifndef DP_VSWING
#define DP_VSWING  4
#endif
#ifndef DP_PREEMPH
#define DP_PREEMPH 1
#endif

static int dp_set_voltage_and_preemphasis(int lanenum, int vswing, int preemph) {
  struct dig_transmitter_control_parameters_v1_6 params = {};
  params.phyid = 0;
  params.action = TRANSMITTER_CONTROL_SET_VOLTAGE_AND_PREEMPASIS;
  params.mode_laneset.dplaneset = (uint8_t)(((vswing & 0x7) << 3) | (preemph & 0x7));
  params.lanenum = lanenum;
  params.symclk_10khz = 0;

  if (!transmitter_control) return -0x5101;
  return transmitter_control(DIG1TRANSMITTERCONTROL, &params);
}

#define PRESLIDE_FUN_PRINTF        0x25D410ULL
#define PRESLIDE_START_EMC_HDMI    0x968DF0ULL
#define PRESLIDE_INIT_VIDEO        0x4B6AF0ULL
#define PRESLIDE_VIDEO_BASIC_CFG   0x4B2570ULL
#define PRESLIDE_HDMI_OUTPUT_MODE  0x4B1FE0ULL
#define PRESLIDE_VIDEO_MUTE_CTRL   0x4B1E80ULL
#define PRESLIDE_RESET_VIDEO_IF    0x4B4370ULL
#define PRESLIDE_GET_DP_LINK_STAT  0x969D50ULL

static uint64_t ktext_base(void) { return (uint64_t)(unsigned long)printf - PRESLIDE_FUN_PRINTF; }

struct ps5_op { uint64_t preslide; int arg; int argc; uint64_t arg2; };

static const struct ps5_op ps5_hdmi_ops[] = {
  { 0x2BB8D0ULL, 0 },
  { 0x2BBB20ULL, 0 },
  { 0x2BBC70ULL, 0 },
  { 0x2BBE30ULL, 0 },
  { 0xBAECD0ULL, 0 },
  { 0x28B970ULL, 0 },
  { 0x6D4F00ULL, 0 },
  { 0xA8F0D0ULL, 0 },
  { 0x4B12D0ULL, 0 },
  { 0x4B14C0ULL, 0 },
  { 0x2BBC40ULL, 0 },

  { 0xB1BA50ULL, 0 },
  { 0xB1C5B0ULL, 0 },
  { 0xB1C7C0ULL, 0 },
  { 0xB1C900ULL, 0 },
  { 0x28CB20ULL, 0 },
  { 0x28CB20ULL, 1 },
  { 0x28CB20ULL, 2 },
  { 0x28CB20ULL, 3 },
  { 0x2BBE60ULL, 0 },
  { 0x4B1690ULL, 0 },
  { 0x4B1810ULL, 0 },

  { 0xB1BB40ULL, 0 },

  { 0x6DA070ULL, 0 },

  { 0x968DF0ULL, 1, 2, 0x7f0ULL },
  { 0x4B6AF0ULL, 0 },
  { 0x4B2570ULL, 1 },
  { 0x4B1FE0ULL, 0 },
  { 0x4B1E80ULL, 0 },
};

#ifndef PS5_OP_LIMIT
#define PS5_OP_LIMIT 0
#endif

int ps5_hdmi_op_count(void) {
  int all = (int)(sizeof(ps5_hdmi_ops) / sizeof(ps5_hdmi_ops[0]));
#if PS5_OP_LIMIT > 0
  return PS5_OP_LIMIT < all ? PS5_OP_LIMIT : all;
#else
  return all;
#endif
}

#ifndef PS5_OP_MASK
#define PS5_OP_MASK 0xFFFFFFFFu
#endif

#define PRESLIDE_ICC_QUERY   0xA3F490ULL
#define PRESLIDE_ICC_QBUF    0x968DA0ULL
#define PRESLIDE_ICC_RBUF    0x968DC0ULL
#define ICC_BUF_SIZE         2032

int ps5_bridge_get(unsigned int reg, unsigned int n, unsigned char *out) {
  int st = ps5_bridge_read_raw(reg, n, out);
  return st;
}

int ps5_bridge_read_raw(unsigned int reg, unsigned int n, unsigned char *out) {
  unsigned char *(*get_q)(int) =
      (unsigned char *(*)(int))(unsigned long)(ktext_base() + PRESLIDE_ICC_QBUF);
  unsigned char *(*get_r)(int) =
      (unsigned char *(*)(int))(unsigned long)(ktext_base() + PRESLIDE_ICC_RBUF);
  int (*icc)(unsigned char *, unsigned char *) =
      (int (*)(unsigned char *, unsigned char *))(unsigned long)(ktext_base() +
                                                                PRESLIDE_ICC_QUERY);
  unsigned char *q = get_q(1);
  unsigned char *r = get_r(1);
  unsigned int i2c_len = 4 + 4 + 4;
  int rc;

  if (!q || !r)
    return -1;
  for (unsigned int i = 0; i < ICC_BUF_SIZE; i++)
    q[i] = 0;

  q[1] = 0x10;
  q[2] = 0; q[3] = 0;
  q[8] = (unsigned char)(12 + i2c_len);
  q[9] = (unsigned char)((12 + i2c_len) >> 8);

  q[12] = 1;
  q[13] = (unsigned char)i2c_len;
  q[14] = (unsigned char)(i2c_len >> 8);
  q[15] = 1;
  q[16] = 1;
  q[17] = 4 + 4;
  q[18] = 1;
  q[19] = 1;
  q[20] = (unsigned char)n;
  q[21] = (unsigned char)(reg >> 8);
  q[22] = (unsigned char)(reg & 0xff);
  q[23] = 0;

  rc = icc(q, r);
  if (rc)
    return -1;

  if (out)
    for (unsigned int i = 0; i < n; i++)
      out[i] = r[20 + i];
  return r[12];
}

void ps5_bridge_probe(const char *when) {
  unsigned char v705f[1] = {0}, v6070[4] = {0}, v60f9[1] = {0}, v6208[4] = {0};
  int s1, s2, s3, s4;

  s1 = ps5_bridge_get(0x705f, 1, v705f);
  s2 = ps5_bridge_get(0x6070, 4, v6070);
  s3 = ps5_bridge_get(0x60f9, 1, v60f9);
  s4 = ps5_bridge_get(0x6208, 4, v6208);

  printf("SCK>BR %s vspe=%02x vs=%d pe=%d phy_rc=%d vs_rc=%d | "
         "705f(%d)=%02x 6070(%d)=%02x%02x%02x%02x 60f9(%d)=%02x 6208(%d)=%02x%02x%02x%02x"
         " | LOCK=%s\n",
         when,
         (unsigned int)g_dp_vspe_raw, (int)g_dp_vswing, (int)g_dp_preemph,
         (int)(int64_t)g_rc_transmitter, (int)(int64_t)g_rc_voltage,
         s1, v705f[0],
         s2, v6070[0], v6070[1], v6070[2], v6070[3],
         s3, v60f9[0],
         s4, v6208[0], v6208[1], v6208[2], v6208[3],
         (v60f9[0] == 0x1b || v6070[0] || v6070[1]) ? "YES" : "no");
}

void call_ps5_hdmi_op(int which) {
  void (*fn)(int);
  if (which < 0 || which >= ps5_hdmi_op_count())
    return;
#if PS5_OP_MASK != 0xFFFFFFFFu
  if (!(((unsigned long long)PS5_OP_MASK >> which) & 1ULL))
    return;
#endif
  fn = (void (*)(int))(unsigned long)(ktext_base() + ps5_hdmi_ops[which].preslide);
  if (ps5_hdmi_ops[which].argc == 2) {
    void (*fn2)(int, uint64_t) =
        (void (*)(int, uint64_t))(unsigned long)(ktext_base() +
                                                ps5_hdmi_ops[which].preslide);
    fn2(ps5_hdmi_ops[which].arg, ps5_hdmi_ops[which].arg2);
    return;
  }
  fn(ps5_hdmi_ops[which].arg);
}

#define PS5_HDMI_BRINGUP_FN   0xB578E0ULL
#define PS5_HDMI_BRINGUP_CTX  0x3D21868ULL

int ps5_hdmi_bringup_call(void) {
  uint64_t ctx = *(volatile uint64_t *)(unsigned long)(ktext_base() + PS5_HDMI_BRINGUP_CTX);

  if (ctx == 0)
    return -1;

  ((void (*)(void))(unsigned long)(ktext_base() + PS5_HDMI_BRINGUP_FN))();
  return 0;
}

#define PS5_HDMI_INIT_FN      0xB579F0ULL
#define PS5_HDMI_IC_TYPE_FN   0x2BBC40ULL
#define PS5_HDMI_GATE_FN      0x2BBE30ULL

int ps5_hdmi_ic_type(void) {
  return ((int (*)(void))(unsigned long)(ktext_base() + PS5_HDMI_IC_TYPE_FN))();
}

int ps5_hdmi_gate_flag(void) {
  return ((int (*)(void))(unsigned long)(ktext_base() + PS5_HDMI_GATE_FN))();
}

void ps5_hdmi_init_call(void) {
  ((void (*)(void))(unsigned long)(ktext_base() + PS5_HDMI_INIT_FN))();
}

static int mp3_set_hdcp_packet(int be, int mode) {
  mp3_req[0] = be;
  mp3_req[1] = mode;
  if (!mp3_invoke) return -0x5102;
  return mp3_invoke(21, mp3_req, mp3_rsp);
}

static int mp3_enable_output(int be, int mode) {
  mp3_req[0] = be;
  mp3_req[1] = mode;
  if (!mp3_invoke) return -0x5103;
  return mp3_invoke(22, mp3_req, mp3_rsp);
}

static void install_hv_code(void) {
  uint64_t identity_cr3 = cave_hv_paging;
  uint64_t identity_pml4_0 = identity_cr3 + 0x1003ULL;
  uint64_t l40_l3_addr = PAGE_PA(identity_pml4_0);
  uint64_t identity_pml40_l3[] = {
      0x0000000000000083,
      0x0000000040000083,
      0x0000000080000083,
      0x00000000C0000083,
      0x0000000100000083
  };
  uint64_t l3_size = sizeof(identity_pml40_l3) / sizeof(identity_pml40_l3[0]);

  *(uint64_t *)PHYS_TO_DMAP(identity_cr3) = identity_pml4_0;
  for (uint64_t i = 0; i < l3_size; i++) {
    *(uint64_t *)PHYS_TO_DMAP(l40_l3_addr + i * 8) = identity_pml40_l3[i];
  }

  uint64_t cave_index = args.hv_code_cave_pa >> 30;
  if (cave_index >= l3_size) {
    *(uint64_t *)PHYS_TO_DMAP(l40_l3_addr + cave_index * 8) =
        (cave_index << 30) | 0x83;
  }

  memcpy((void *)PHYS_TO_DMAP(cave_hv_code), shellcode_hv_bin,
         shellcode_hv_bin_len);
}

void patch_hv(void) {
  if (args.hv_code_cave_pa > 0x7fffffffULL) {
    uint8_t shellcode_jmp[] = {0x48, 0xB8, 0xAA, 0xAA, 0xAA,
                               0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                               0xFF, 0xE0};
    *(uint64_t *)(&shellcode_jmp[2]) = args.hv_code_cave_pa;
    memcpy((void *)PHYS_TO_DMAP(args.hv_handle_vmexit_pa), shellcode_jmp,
           sizeof(shellcode_jmp));
  } else {
    uint8_t shellcode_jmp[] = {0x48, 0xC7, 0xC0, 0xAA,
                               0xAA, 0xAA, 0xAA,
                               0xFF, 0xE0};

    *(uint32_t *)(&shellcode_jmp[3]) = (uint32_t)args.hv_code_cave_pa;

    memcpy((void *)PHYS_TO_DMAP(args.hv_handle_vmexit_pa), shellcode_jmp,
           sizeof(shellcode_jmp));
  }

  uint8_t shellcode_identity_and_jmp[] = {
      0x48, 0xB8, 0xAA, 0xAA, 0xAA,
      0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
      0x0F, 0x22, 0xD8,
      0x48, 0xB8, 0xAA, 0xAA, 0xAA,
      0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
      0xFF, 0xE0
  };

  *(uint64_t *)(&shellcode_identity_and_jmp[2]) = cave_hv_paging;

  *(uint64_t *)(&shellcode_identity_and_jmp[15]) = cave_hv_code;

  memcpy((void *)PHYS_TO_DMAP(args.hv_code_cave_pa), shellcode_identity_and_jmp,
         sizeof(shellcode_identity_and_jmp));
}

static void m(const char *s) {
  g_step++;
  printf("%s", s);
}

static void m_hex(const char *label, uint64_t v) {
  char buf[64];
  int i = 0, j;
  while (label[i] && i < 38) { buf[i] = label[i]; i++; }
  buf[i++] = '=';
  buf[i++] = '0';
  buf[i++] = 'x';
  for (j = 15; j >= 0; j--) {
    int nib = (int)((v >> (j * 4)) & 0xF);
    buf[i++] = (char)(nib < 10 ? '0' + nib : 'a' + nib - 10);
  }
  buf[i++] = '\n';
  buf[i] = 0;
  puts_uart(args.dmap_base, (const uint8_t *)buf);
}

static void delay_ms(uint32_t ms) {
  uint32_t lo, hi;
  uint64_t start, now;
  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
  start = ((uint64_t)hi << 32) | lo;
  do {
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    now = ((uint64_t)hi << 32) | lo;
  } while (now - start < (uint64_t)ms * 3500000ULL);
}

void boot_linux(void) {
  int rc;
  m("SCK>B0-enter\n");
  patch_hv();
  m("SCK>B1-patch_hv-done\n");

  install_hv_code();
  m("SCK>B2-install_hv_code-done\n");

  memcpy((void *)PHYS_TO_DMAP(0xC0000), (void *)g_vbios, 0x10000);
  m("SCK>B3-vbios-done\n");

  rc = dp_enable_link_phy(4, 30);
  g_rc_transmitter = (uint64_t)(int64_t)rc;
  m_hex("SCK>B4-dp-link-rc", g_rc_transmitter);

#ifdef PS5_NO_VSWING

  g_rc_voltage = 0xD15AB1EDULL;
#else
  {
    unsigned char vspe =
        *(volatile unsigned char *)(unsigned long)(ktext_base() + PRESLIDE_DP_VSPE);
    int vs = DP_VSWING, pe = DP_PREEMPH;

    if (vspe != 0xFF) {
      vs = (vspe >> 3) & 7;
      pe = vspe & 7;
    }
    g_dp_vspe_raw = vspe;
    g_dp_vswing = (uint64_t)vs;
    g_dp_preemph = (uint64_t)pe;
    rc = dp_set_voltage_and_preemphasis(4, vs, pe);
  }
  g_rc_voltage = (uint64_t)(int64_t)rc;
  m_hex("SCK>B4a-vswing-rc", g_rc_voltage);
#endif

  delay_ms(100);
  m("SCK>B4b-delay-done\n");

  rc = mp3_initialize ? mp3_initialize(0) : -0x5104;
  g_rc_mp3_init = (uint64_t)(int64_t)rc;
  m_hex("SCK>B5a-mp3init-rc", g_rc_mp3_init);
  rc = mp3_set_hdcp_packet(0, 1);
  g_rc_mp3_hdcp = (uint64_t)(int64_t)rc;
  m_hex("SCK>B5b-hdcp-rc", g_rc_mp3_hdcp);
  rc = mp3_enable_output(0, 1);
  g_rc_mp3_output = (uint64_t)(int64_t)rc;
  m_hex("SCK>B5c-output-rc", g_rc_mp3_output);
  m("SCK>B5-mp3-done\n");

  memcpy(&info, (void *)args.linux_info_va, sizeof(struct linux_info));
  m("SCK>B6-linux_info-copied\n");

  info.n_tmrs = 0;
  if (args.fw_version >= 0x0500 && args.fw_version < 0x0800) {
    SceSblHvShm *shm = (SceSblHvShm *)PHYS_TO_DMAP(get_hv_shm());

    for (int i = 0; i < 64; i++) {
      if (shm->tmrPtStates[i].flags & 1) {
        info.tmrs[info.n_tmrs].start = shm->tmrPtStates[i].addr;
        info.tmrs[info.n_tmrs].end = shm->tmrPtStates[i].addr + shm->tmrPtStates[i].size;
        printf("tmr: %lx-%lx\n", info.tmrs[info.n_tmrs].start, info.tmrs[info.n_tmrs].end);
        info.n_tmrs++;
      }
    }
  }

  uintptr_t bzimage = info.bzimage;
  uintptr_t initrd = info.initrd;

  info.bzimage = cave_bzImage;
  info.initrd = cave_bzImage + ALIGN_UP(info.bzimage_size, PAGE_SIZE);

  memcpy((void *)PHYS_TO_DMAP(cave_linux_info), &info,
         sizeof(struct linux_info));
  m("SCK>B7-linux_info-staged\n");
  memcpy((void *)PHYS_TO_DMAP(info.bzimage), (void *)bzimage,
         info.bzimage_size);
  m("SCK>B8-bzimage-copied\n");
  memcpy((void *)PHYS_TO_DMAP(info.initrd), (void *)initrd, info.initrd_size);
  m("SCK>B9-initrd-copied\n");
}
