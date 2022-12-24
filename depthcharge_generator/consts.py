#Config

ZIP_EOCD_SIZE=0x16
ZIP_EOCD_SIGNATURE=0x06054b50

#Constants for reboot
HBOOT_REASON_ADDR = 0xbf7fe000
HBOOT_REASON_FASTBOOT = 0x77665500
HBOOT_REASON_RECOVERY = 0x77665502
HBOOT_REASON_HBOOT = 0x77665503
PMC_ADDR = 0x7000E400
PMC_REBOOT = 0x10

#Apparently flashing hboot's bigger or smaller than this causes bricks (without triggering APX due to signature being OK) so we make sure that doesnt happen
HBOOT_LENGTH = 0x200010

#Tegra 3 address where bootloader is loaded
BL_LOAD_ADDRESS = 0x80108000

BCT_PART_SIZE_MAX = 0x400000
BL_PART_SIZE_MAX = 0x400000

FAILURE_DUMP_ADDR = 0xBADDEAD0

CHECKSUM_MASK = 0xA5A5A5A5

MAGIC = 0xC0DECAFE

#Where HBoot version string is located
HBOOT_VERSION_ADDR = 0x80108004

########################################################################################################################
#HBoot specifics

#This contains per HBoot version specific values:
# fastboot_start: Addresses where fastboot recv buffer starts, use utils -> generate_localizer to obtain this address for other versions
# fastboot_padding: Amount of padding to add for payload placement, this has to be big enough to avoid crashing
# exploit_hotfix_addr: Address to patch the exploit and avoid crashing upon rerun
# hijack_addr: Hijack point, right after "Please plug off USB" once SD update func finishes is showed and method to wait unplug is called
# thread_kill_func: ARM mode function that will stop current thread and switch to other thread
# jump_to_func: Thumb mode function that will launch our modified hboot binary, it contains "jump to 0x%x\n". Args: img_ptr, img_len
# print_log_func: Thumb mode function that prints a string. Args: text_ptr, color
# sleep_func: ARM mode function that sleeps ms. Args: millis
# main_thread_ptr: Pointer where main thread struct is located
HBOOT_CONFIG = {
    "1.36.0000": {
        "fastboot_start":   0x806be220,
        "fastboot_padding":  0x1000000,
        "thread_kill_func": 0x801a7cac,
        "jump_to_func": 0x8011ef2c + 1,
        "print_log_func": 0x8010eae4 + 1,
        "mode_normal": {
            "exploit_hotfix_addr": 0x8012f050,
            "hijack_addr": 0x80118ad0,
        },
        "mode_immediate": {
            "sleep_func": 0x801a7db0,
            "main_thread_ptr": 0x802c0b30,
        }
    },
    "1.72.0000": {
        "fastboot_start":   0x806beee0,
        "fastboot_padding":  0x1000000,
        "thread_kill_func": 0x801a879c,
        "jump_to_func": 0x8011f31c + 1,
        "print_log_func": 0x8010eb80 + 1,
        "mode_normal": {
            "exploit_hotfix_addr": 0x8012f9b8,
            "hijack_addr": 0x80118dbc,
        },
        "mode_immediate": {
            "sleep_func": 0x801a88a0,
            "main_thread_ptr": 0x802c1760,
        }
    },
}

########################################################################################################################
#Patched HBoot 1.72 specifics used for flashing

FUNCTION_REBOOT_ADDR = 0x80132ab8 + 1
FUNCTION_PRINT_ADDR = 0x801a3728
FUNCTION_WRITE_PARTITION_OFFSET = 0x8011b9dc + 1

FLASHER_MAGIC_ADDR = 0x801b1158 - BL_LOAD_ADDRESS
FLASHER_MAGIC_VALUE = 0xCAFEC0DE
FLASHER_ADDRESS_ADDR = FLASHER_MAGIC_ADDR + 4
