#ifndef BOOT_LINUX_H
#define BOOT_LINUX_H

#include <stdint.h>

#define ALIGN_UP(size, align) (((size) + (align) - 1) & ~((align) - 1))

static int dp_enable_link_phy(int lanenum, int linkrate);
static void install_hv_code(void);
void boot_linux(void);

extern int (*transmitter_control)(int cmd, void *control);
extern int (*mp3_initialize)(int vmid);
extern int (*mp3_invoke)(int cmd_id, void *req, void *rsp);

extern uint64_t g_vbios;

extern uint64_t g_step;
extern uint64_t g_rc_transmitter;
extern uint64_t g_rc_voltage;

int  ps5_hdmi_op_count(void);
void call_ps5_hdmi_op(int which);
int  ps5_bridge_read_raw(unsigned int reg, unsigned int n, unsigned char *out);
int  ps5_bridge_get(unsigned int reg, unsigned int n, unsigned char *out);
void ps5_bridge_probe(const char *when);
int  ps5_hdmi_bringup_call(void);
int  ps5_hdmi_ic_type(void);
int  ps5_hdmi_gate_flag(void);
void ps5_hdmi_init_call(void);
void call_ps5_display_bringup(void);
extern uint64_t g_rc_mp3_init;
extern uint64_t g_rc_mp3_hdcp;
extern uint64_t g_rc_mp3_output;

#endif
