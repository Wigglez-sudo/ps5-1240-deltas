#include "offsets.h"

#define KERNEL_TEXT 0xFFFFFFFF80210000

offset_list off_1360 = {
    .IOMMU_SOFTC        = 0x3543A70,

    .VMSPACE_VM_VMID    = 0x1EC,
    .VMSPACE_VM_PMAP    = 0x1D8,

    .DATA_BASE_GVMSPACE = 0x3BAA570,

    .ACPIGBL_FACS       = 0x39C9490,
    .IDT                = 0x3BB4300,
    .COMMON_TSS         = 0x3BB6FE0,
    .FUN_MEMCPY         = 0x2590B0,

    .STOPPED_CPUS       = 0,
    .FUN_STOP_CPUS      = 0,
    .FUN_AS_LAPIC_EOI   = 0,
    .FUN_HV_UNMAP_PT_TMR = 0,
    .HOOK_ACPI_WAKEUP_MACHDEP = 0x3912CB,

    .GAD_ADD_RSP_28_POP_RBP_RET = 0x9E32B4,
    .GAD_IRETQ            = 0x257B3D,
    .GAD_POP_RAX_RET      = 0xB8CA6E,
    .GAD_POP_RDI_RET      = 0x28CE6D,
    .GAD_POP_RSI_RET      = 0x34CB91,
    .GAD_POP_RDX_RET      = 0x2A0F7B,
    .GAD_POP_RCX_RET      = 0x2918B2,
    .GAD_POP_RSP_RET      = 0xB8291B,
    .GAD_WRMSR_RET        = 0x255034,
    .GAD_MOV_QWORD_PTR_RDI_RSI_POP_RBP_RET = 0x3D3F2A,

    .KERNEL_SYM_HV_MP_STARTUP_CALL     = 0xC16EE0,
    .KERNEL_SYM_MP_STARTUP_INIT_VECTOR = 0x269FB8,
    .KERNEL_SYM_DATA_CAVE              = 0x2D39000,

    .GAD_PIVOT_ADD_RSP28_RET  = 0x25213E,

    .GAD_POP_R8_RET           = 0xB8CA6D,
    .GAD_STORE_RCX_R8_RET     = 0x474389,
    .GAD_STORE_RDI8_RCX_RET   = 0x32693F,
    .GAD_OR_RCX_EAX_RET       = 0x321EA0,
    .GAD_SET_DR7_RAX          = 0xA07BA6,
    .GAD_ST_RCX_RDX_RET       = 0x82B915,

    .GAD_ST_RCX_RAX_RET       = 0x2BB28F,
    .GAD_MOV_RAX_RSI_RET      = 0x8E3A44,
    .GAD_MOV_RAX_RDI_RET      = 0xBECDEA,
    .GAD_REP_MOVSB            = 0x25D027,
    .GAD_CLD_RET              = 0x30644F,
    .GAD_RET_TRAMP            = 0x2912A2,
    .GAD_DBREG_RESUME         = 0x2529D8,

    .KERNEL_CODE_CAVE          = 0xCB92C0,

    .FUN_PRINTF                = 0x25D410,
    .FUN_HV_IOMMU_SET_BUFFERS  = 0xC16B00,
    .FUN_HV_IOMM_WAIT_COMPLETION = 0xC16A40,

    .FUN_SMP_RENDEZVOUS        = 0xB03BA0,

    .FUN_SMP_NO_RENDEVOUS_BARRIER = 0x261E08,

    .HV_CODE_CAVE_PA           = 0x62806F00,
    .HV_HANDLE_VMEXIT_PA       = 0x62847375,

    .KERNEL_UART_OVERRIDE      = 0x21F9598,

    .KERNEL_CFI_CHECK          = 0x44F8C0,

    .G_VBIOS                   = 0x3DDB9F0,

    .FUN_TRANSMITTER_CONTROL   = 0xC0EAA0,

    .FUN_MP3_INITIALIZE        = 0xA14130,
    .FUN_MP3_INVOKE            = 0xA12D30,

    .PS5_WIFI_FW_OFFSET        = 0x1518160,
    .PS5_WIFI_FW_SIZE          = 500296,

    .NVS_SIZETAB      = 0x1A1A030,
    .PRELOAD_METADATA = 0x3DF1070,
};

offset_list off_1240 = {
    .IOMMU_SOFTC        = 0x3599510,
    .VMSPACE_VM_VMID    = 0x1FC,
    .VMSPACE_VM_PMAP    = 0x1D8,
    .DATA_BASE_GVMSPACE = 0x2E7E570,

    .ACPIGBL_FACS       = 0x3A04C80,
    .IDT                = 0x3BD8300,
    .COMMON_TSS         = 0x3BDAFE0,
    .FUN_MEMCPY         = 0x2EF0C0,

    .STOPPED_CPUS       = 0,
    .FUN_STOP_CPUS      = 0,
    .FUN_AS_LAPIC_EOI   = 0,
    .FUN_HV_UNMAP_PT_TMR = 0,
    .HOOK_ACPI_WAKEUP_MACHDEP = 0x43C150,

    .GAD_ADD_RSP_28_POP_RBP_RET = 0xA70CE4,
    .GAD_IRETQ            = 0x2B34AD,
    .GAD_POP_RAX_RET      = 0x26E8D0,
    .GAD_POP_RDI_RET      = 0x251C78,
    .GAD_POP_RSI_RET      = 0x2127B0,
    .GAD_POP_RDX_RET      = 0x34F4EB,
    .GAD_POP_RCX_RET      = 0x3410D2,
    .GAD_POP_RSP_RET      = 0x2B6310,
    .GAD_WRMSR_RET        = 0x2B09A4,
    .GAD_MOV_QWORD_PTR_RDI_RSI_POP_RBP_RET = 0x47E94A,

    .KERNEL_CODE_CAVE     = 0x1232F0,
    .FUN_PRINTF           = 0x544190,
    .FUN_HV_IOMMU_SET_BUFFERS  = 0xC9DB70,
    .FUN_HV_IOMM_WAIT_COMPLETION = 0xC9DAB0,
    .FUN_SMP_RENDEZVOUS   = 0xB8FB60,
    .FUN_SMP_NO_RENDEVOUS_BARRIER = 0x31D9B0,

    .HV_CODE_CAVE_PA      = 0x62806F00,
    .HV_HANDLE_VMEXIT_PA  = 0x6283374D,

    .KERNEL_UART_OVERRIDE = 0x2275CD8,
    .KERNEL_CFI_CHECK     = 0x4F9E50,

    .G_VBIOS              = 0x3DF79F0,
    .FUN_TRANSMITTER_CONTROL = 0xC95A70,
    .FUN_MP3_INITIALIZE   = 0xAA1FD0,
    .FUN_MP3_INVOKE       = 0xAA0BD0,

    .PS5_WIFI_FW_OFFSET   = 0x15A83F0,

    .PS5_WIFI_FW_SIZE     = 0x799C0,

    .KERNEL_SYM_HV_MP_STARTUP_CALL     = 0xC9DF50,
    .KERNEL_SYM_MP_STARTUP_INIT_VECTOR = 0x318678,
    .KERNEL_SYM_DATA_CAVE              = 0x2DB5000,

    .GAD_PIVOT_ADD_RSP28_RET  = 0x2A815E,
    .GAD_POP_R8_RET           = 0xC18C8D,
    .GAD_STORE_RCX_R8_RET     = 0x51E699,
    .GAD_STORE_RDI8_RCX_RET   = 0x3D66DF,
    .GAD_OR_RCX_EAX_RET       = 0x899E20,
    .GAD_SET_DR7_RAX          = 0xA95A36,
    .GAD_ST_RCX_RDX_RET       = 0x8BBA75,
    .GAD_ST_RCX_RAX_RET       = 0x369DEF,
    .GAD_MOV_RAX_RSI_RET      = 0x971E64,
    .GAD_MOV_RAX_RDI_RET      = 0x2B9D91,
    .GAD_REP_MOVSB            = 0x30B6C7,
    .GAD_CLD_RET              = 0x36A530,
    .GAD_RET_TRAMP            = 0x26E8D1,
    .GAD_DBREG_RESUME         = 0x2AC9F8,

    .GAD_STORE_RDI_RAX_RET    = 0,
    .GAD_OR_RSI_ECX_RET       = 0,

    .NVS_SIZETAB      = 0x1A8A900,
    .PRELOAD_METADATA = 0,

};

offset_list off_1270 = {
    .IOMMU_SOFTC                            = 0x3599510,
    .VMSPACE_VM_VMID                        = 0x1FC,
    .VMSPACE_VM_PMAP                        = 0x1D8,
    .DATA_BASE_GVMSPACE                     = 0x2E7E570,
    .ACPIGBL_FACS                           = 0x3A04C80,
    .IDT                                    = 0x3BD8300,
    .FUN_MEMCPY                            = 0x2EF0C0,
    .COMMON_TSS                             = 0x3BDAFE0,
    .STOPPED_CPUS                           = 0x0,
    .FUN_STOP_CPUS                          = 0x0,
    .FUN_AS_LAPIC_EOI                       = 0x0,
    .FUN_HV_UNMAP_PT_TMR                    = 0x0,
    .HOOK_ACPI_WAKEUP_MACHDEP               = 0x43C150,
    .GAD_ADD_RSP_28_POP_RBP_RET             = 0xA70D44,
    .GAD_IRETQ                              = 0x2B34AD,
    .GAD_POP_RAX_RET                        = 0x26E8D0,
    .GAD_POP_RDI_RET                        = 0x251C78,
    .GAD_POP_RSI_RET                        = 0x2127B0,
    .GAD_POP_RDX_RET                        = 0x34F4EB,
    .GAD_POP_RCX_RET                        = 0x3410D2,
    .GAD_POP_RSP_RET                        = 0x2B6310,
    .GAD_WRMSR_RET                          = 0x2B09A4,
    .GAD_MOV_QWORD_PTR_RDI_RSI_POP_RBP_RET  = 0x47E94A,
    .KERNEL_CODE_CAVE                       = 0x1232F0,
    .FUN_PRINTF                             = 0x544190,
    .FUN_HV_IOMMU_SET_BUFFERS               = 0xC9DBD0,
    .FUN_HV_IOMM_WAIT_COMPLETION            = 0xC9DB10,
    .FUN_SMP_RENDEZVOUS                     = 0xB8FBC0,
    .FUN_SMP_NO_RENDEVOUS_BARRIER           = 0x31D9B0,
    .HV_CODE_CAVE_PA                        = 0x62806F00,
    .HV_HANDLE_VMEXIT_PA                    = 0x6283374D,
    .KERNEL_UART_OVERRIDE                   = 0x2275CD8,
    .KERNEL_CFI_CHECK                       = 0x4F9E50,
    .G_VBIOS                                = 0x3DF79F0,
    .FUN_TRANSMITTER_CONTROL                = 0xC95AD0,
    .FUN_MP3_INITIALIZE                     = 0xAA2030,
    .FUN_MP3_INVOKE                         = 0xAA0C30,
    .PS5_WIFI_FW_OFFSET                     = 0x15A83F0,
    .PS5_WIFI_FW_SIZE                       = 0x799C0,
    .KERNEL_SYM_HV_MP_STARTUP_CALL          = 0xC9DFB0,
    .KERNEL_SYM_MP_STARTUP_INIT_VECTOR      = 0x318678,
    .KERNEL_SYM_DATA_CAVE                   = 0x2DB5000,
    .GAD_PIVOT_ADD_RSP28_RET                = 0x2A815E,
    .GAD_POP_R8_RET                         = 0xC18CED,
    .GAD_STORE_RCX_R8_RET                   = 0x51E699,
    .GAD_STORE_RDI8_RCX_RET                 = 0x3D66DF,
    .GAD_OR_RCX_EAX_RET                     = 0x899E20,
    .GAD_SET_DR7_RAX                        = 0xA95A96,
    .GAD_ST_RCX_RDX_RET                     = 0x8BBA75,
    .GAD_ST_RCX_RAX_RET                     = 0x369DEF,
    .GAD_MOV_RAX_RSI_RET                    = 0x971E64,
    .GAD_MOV_RAX_RDI_RET                    = 0x2B9D91,
    .GAD_REP_MOVSB                          = 0x30B6C7,
    .GAD_CLD_RET                            = 0x36A530,
    .GAD_RET_TRAMP                          = 0x26E8D1,
    .GAD_DBREG_RESUME                       = 0x2AC9F8,
    .GAD_STORE_RDI_RAX_RET                  = 0x0,
    .GAD_OR_RSI_ECX_RET                     = 0x0,
    .NVS_SIZETAB                            = 0x1A8A900,
    .PRELOAD_METADATA                       = 0x0,
};
