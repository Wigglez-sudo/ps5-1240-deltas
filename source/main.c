#include "hv_defeat_13xx.h"
#include "loader.h"
#include "prepare_resume.h"
#include "utils.h"
#include <unistd.h>

int main(void) {
  if (setup_env()) {
    notify("Something went wrong while initiating.\nPlease make sure your fw "
           "is supported.");
    return -1;
  }

  if (fetch_linux(&linux_i)) {
    notify("Something went wrong while installing linux files.\n");
    return -1;
  }

  void *shellcode_kernel;
  size_t shellcode_kernel_len;
  if (prepare_resume(&shellcode_kernel, &shellcode_kernel_len)) {
    notify("Something went wrong while preparing resume.\n");
    return -1;
  }

  if (!env_offset.HV_HANDLE_VMEXIT_PA || !env_offset.HV_CODE_CAVE_PA) {
    notify("fw %x: HV patch addresses missing from the offset table "
           "(HV_HANDLE_VMEXIT_PA=%lx HV_CODE_CAVE_PA=%lx).\n"
           "These live in the HYPERVISOR image, not x86_kernel.elf, and cannot be derived "
           "from the kernel. Refusing to arm rather than patching physical page 0.",
           fw, (unsigned long)env_offset.HV_HANDLE_VMEXIT_PA,
           (unsigned long)env_offset.HV_CODE_CAVE_PA);
    goto err;
  }

  if ((0x1200 <= fw) && (fw < 0x1400)) {
    if (hv_defeat_13xx(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else {
    goto err;
  }

  notify("Finished preparation. Going to rest mode in 5 seconds.\nPlease wait "
         "for the orange light to stop "
         "blinking and then wakeup to Linux :)\n");

  sleep(5);
  enter_rest_mode();

  while (1) {
    sleep(30);
  }

  return 0;

err:
  notify("Something went wrong while defeating Hypervisor.\nPlease make sure "
         "your fw is supported.");
  return -1;
}
