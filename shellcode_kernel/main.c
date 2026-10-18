#include "main.h"
#include "boot_linux.h"
#include "hv_defeat_0304.h"
#include "utils.h"
#include <stddef.h>

shellcode_kernel_args args = {0};

__attribute__((section(".entry_point"))) uint32_t main(uint64_t add1,
                                                       uint64_t add2) {
  volatile shellcode_kernel_args *args_ptr =
      (volatile shellcode_kernel_args
           *)0x11AA11AA11AA11AA;

  __asm__ volatile("" : "+r"(args_ptr));

  mark(args_ptr, "SCK>0-entered\n");

  if ((args_ptr->fun_printf & 0xFFFF) == 0) {
    return -1;
  }

  ((void (*)(const char *, ...))args_ptr->fun_printf)("SCK>ENTRY-main-reached\n");

  activate_uart(args_ptr);
  mark(args_ptr, "SCK>1-uart\n");

  if ((0x0300 <= args_ptr->fw_version) && (args_ptr->fw_version < 0x0500)) {
    if (hv_defeat_0304(args_ptr))
      return -1;
  } else if ((0x0500 <= args_ptr->fw_version) &&
             (args_ptr->fw_version < 0x0800)) {
  } else if ((0x1200 <= args_ptr->fw_version) &&
             (args_ptr->fw_version < 0x1400)) {
  } else {
    return 0;
  }

  mark(args_ptr, "SCK>2-fw-dispatch-passed\n");

  init_global_pointers(args_ptr);
  printf("SCK>3-globals\n");

  *(uint8_t *)args_ptr->kernel_cfi_check = 0xC3;
  printf("SCK>4-cfi-patched\n");

  boot_linux();

  printf("SCK>5-boot-linux-RETURNED\n");
  printf("SCK>5a-steps-reached=0x%llx\n", (unsigned long long)g_step);
  printf("SCK>5b-transmitter-rc=0x%llx\n", (unsigned long long)g_rc_transmitter);
  printf("SCK>5f-vswing-rc=0x%llx\n", (unsigned long long)g_rc_voltage);
  printf("SCK>5c-mp3init-rc=0x%llx\n", (unsigned long long)g_rc_mp3_init);
  printf("SCK>5d-hdcp-rc=0x%llx\n", (unsigned long long)g_rc_mp3_hdcp);
  printf("SCK>5e-output-rc=0x%llx\n", (unsigned long long)g_rc_mp3_output);

#ifdef PS5_NO_HDMI_OPS
  if (0) {
#else
  if (0x1300 <= args_ptr->fw_version && args_ptr->fw_version < 0x1400) {
#endif

  printf("SCK>5h-ps5-ops-begin\n");
  for (int i = 0; i < ps5_hdmi_op_count(); i++) {
    printf("SCK>5h-op-%d-starting\n", i + 1);
    call_ps5_hdmi_op(i);
    printf("SCK>5h-op-%d-ok\n", i + 1);
  }
  printf("SCK>5h-ps5-ops-done\n");
  } else {
    printf("SCK>5h-skipped: HDMI ops are 13.60-only offsets, fw=0x%x\n",
           args_ptr->fw_version);
  }
  printf("Linux prepared OK\n");

  printf("Good Bye VM :)\n");
  mark(args_ptr, "SCK>6-rendezvous-starting\n");
  smp_rendezvous(smp_no_rendevous_barrier, vmmcall_dummy,
                 smp_no_rendevous_barrier, NULL);
  mark(args_ptr, "SCK>7-rendezvous-RETURNED\n");

  printf("We shouldn't be here :(\n");
  return 0;
}
