#include "loader.h"
#include "config.h"
#include "firmware.h"
#include "linux.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

const char *file_paths[] = {
    "/mnt/usb0/",           "/mnt/usb1/",           "/mnt/usb2/",
    "/mnt/usb3/",           "/mnt/usb0/PS5/Linux/", "/mnt/usb1/PS5/Linux/",
    "/mnt/usb2/PS5/Linux/", "/mnt/usb3/PS5/Linux/",
};

long find_and_get_size_of_file(const char *filename, char *found_path);
int find_and_read_file(const char *filename, void *buf, size_t bufsize);

static const char *get_overridden_filename(const char *filename) {
  static int state = 0;
  static char *overrides_start = nullptr;
  static char *overrides_end = nullptr;

  if (state == 0) {
    state = 1;
    char found_path[256];
    ssize_t size = find_and_get_size_of_file("path-override.txt", found_path);
    if (size > 0) {
      overrides_start = malloc(size + 1);
      overrides_end = overrides_start + size + 1;
      if (read_file(found_path, overrides_start, size) == size) {
        state = 2;
        for (char *p = overrides_start; p < overrides_end; p++)
          if (*p == '\n')
            *p = 0;

        overrides_start[size] = 0;
      }
    }
  }

  if (state == 1)
    return filename;

  size_t needle_len = strlen(filename);
  for (const char *p = overrides_start; p < overrides_end;) {
    size_t haystack_len = strlen(p);
    if (haystack_len > needle_len && !strncmp(p, filename, needle_len) &&
        p[needle_len] == '=')
      return p + needle_len + 1;
    p += haystack_len + 1;
  }

  return filename;
}

long find_and_get_size_of_file(const char *filename, char *found_path) {
  char full_path[256];
  struct stat st;

  filename = get_overridden_filename(filename);
  int num_paths = sizeof(file_paths) / sizeof(file_paths[0]);

  for (int i = 0; i < num_paths; i++) {
    snprintf(full_path, sizeof(full_path), "%s%s", file_paths[i], filename);

    if (stat(full_path, &st) == 0) {
      notify("File '%s' found in '%s'\n", filename, file_paths[i]);
      strcpy(found_path, full_path);
      return st.st_size;
    }
  }

  return -1;
}

int find_and_read_file(const char *filename, void *buf, size_t bufsize) {
  char full_path[256];
  struct stat st;

  int num_paths = sizeof(file_paths) / sizeof(file_paths[0]);

  for (int i = 0; i < num_paths; i++) {
    snprintf(full_path, sizeof(full_path), "%s%s", file_paths[i], filename);

    if (stat(full_path, &st) == 0) {
      notify("File '%s' found in '%s'\n", filename, file_paths[i]);
      return read_file(full_path, buf, bufsize);
    }
  }

  return -1;
}

int read_file(const char *path, void *buf, size_t bufsize) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return fd;
  int r = read(fd, buf, bufsize);
  close(fd);
  return r;
}

static int read_file_until_eof(const char *path, void *buf, size_t max) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return fd;
  size_t total = 0;
  while (total < max) {
    ssize_t n = read(fd, (char *)buf + total, max - total);
    if (n < 0) {
      int e = errno;
      close(fd);
      errno = e;
      return -1;
    }
    if (n == 0)
      break;
    total += (size_t)n;
  }
  close(fd);
  return (int)total;
}

void trim_newline(char *s) {
  while (*s != '\0') {
    if (*s == '\r' || *s == '\n') {
      *s = '\0';
      break;
    }
    s++;
  }
}

int fetch_linux(struct linux_info *info) {
  char bzimage_path[256];
  char initrd_path[256];

  long bzimage_stat = -1;
  for (int attempt = 0; attempt < 12; attempt++) {
    bzimage_stat = find_and_get_size_of_file("bzImage", bzimage_path);
    if (bzimage_stat > 0 && bzimage_stat < 0x8000000) break;
    if (attempt == 0) notify("Waiting for the Linux media to come up...\n");
    usleep(1000000);
  }
  if (bzimage_stat < 0) {
    notify("File bzImage not found at default paths - Aborting\n");
    return -1;
  }

  size_t bzimage_map = bzimage_stat ? ALIGN_UP((size_t)bzimage_stat, PAGE_SIZE)
                                    : (64u << 20);
  void *bzimage = mmap(NULL, bzimage_map, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (bzimage == MAP_FAILED) {
    int e = errno;
    notify("[-] Error could not allocate bzimage (%d bytes, errno %d).\n",
           (int)bzimage_map, e);
    return -1;
  }

  int bzimage_got = read_file_until_eof(bzimage_path, bzimage, bzimage_map);
  if (bzimage_got <= 0) {
    notify("Something went wrong while reading bzImage - Aborting\n");
    return -1;
  }
  if (bzimage_stat == 0)
    notify("[*] bzImage reported size 0; read %d bytes until EOF.\n", bzimage_got);
  size_t bzimage_size = (size_t)bzimage_got;

  long initrd_stat = find_and_get_size_of_file("initrd.img", initrd_path);
  if (initrd_stat < 0) {
    notify("File initrd.img not found at default paths - Aborting\n");
    return -1;
  }

  size_t initrd_map = initrd_stat ? ALIGN_UP((size_t)initrd_stat, PAGE_SIZE)
                                  : (256u << 20);
  void *initrd = mmap(NULL, initrd_map, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (initrd == MAP_FAILED) {
    int e = errno;
    notify("[-] Error could not allocate initrd (%d bytes, errno %d).\n",
           (int)initrd_map, e);
    return -1;
  }

  int initrd_got = read_file_until_eof(initrd_path, initrd, initrd_map);
  if (initrd_got <= 0) {
    notify("Something went wrong while reading initrd - Aborting\n");
    return -1;
  }
  if (initrd_stat == 0)
    notify("[*] initrd.img reported size 0; read %d bytes until EOF.\n", initrd_got);
  size_t initrd_size = (size_t)initrd_got;

  if (dump_device_firmwares(initrd_path) < 0) {
    notify(
        "Something went wrong while dumping device firmwares - Continuing\n");
  }

  size_t vram_size;
  char buf_vram[16] = {};
  int ret = find_and_read_file("vram.txt", buf_vram, sizeof(buf_vram) - 1);
  if (ret < 0) {
    printf(
        "File vram.txt not found at default paths - Using static fallback\n");
    vram_size = VRAM_SIZE;
  } else {
    trim_newline(buf_vram);
    vram_size = strtoull(buf_vram, NULL, 16);
    if (vram_size == 0) {
      printf("Seems like the configured vram value is wrong - Using static "
             "fallback\n");
      vram_size = VRAM_SIZE;
    }
  }

  char cmdline[2048] = {};
  ret = find_and_read_file("cmdline.txt", cmdline, sizeof(cmdline) - 1);
  if (ret < 0) {
    printf("File cmdline.txt not found at default paths - Using static "
           "fallback\n");
    strcpy(cmdline, CMD_LINE);
  } else {
    trim_newline(cmdline);
  }

#define EXTRA_CMDLINE " rootdelay=20 usb-storage.delay_use=15"
  {
    size_t l = strlen(cmdline);
    size_t i = 0;
    while (EXTRA_CMDLINE[i] && l + i < sizeof(cmdline) - 1) {
      cmdline[l + i] = EXTRA_CMDLINE[i];
      i++;
    }
    cmdline[l + i] = '\0';
  }

  info->linux_info = kernel_cave_linux_info;
  info->bzimage = kernel_cave_bzImage;
  info->bzimage_size = bzimage_size;
  info->initrd = kernel_cave_bzImage + ALIGN_UP(bzimage_size, PAGE_SIZE);
  info->initrd_size = initrd_size;
  info->vram_size = vram_size;
  info->kit_type = (int)get_kit_type();
  strcpy(info->cmdline, cmdline);

  uint64_t page = alloc_page();
  kwrite(pa_to_dmap(page), info, sizeof(struct linux_info));
  install_page_syscore(kernel_cave_linux_info, page, 0);

  for (int i = 0; i < bzimage_size; i += PAGE_SIZE) {
    install_page_syscore(info->bzimage + i,
                         vtophys_user((uintptr_t)bzimage + i), 0);
  }

  for (int i = 0; i < initrd_size; i += PAGE_SIZE) {
    install_page_syscore(info->initrd + i, vtophys_user((uintptr_t)initrd + i),
                         0);
  }

  return 0;
}
