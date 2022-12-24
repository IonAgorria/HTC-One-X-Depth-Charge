import utils
import asm
import consts
import crypto

def encrypt_payload(args):
    #Encrypt stuff to flash as under diag the crypto engine is reset, so can't encrypt

    #Load and encrypt bootloader
    with open(args.bl, 'rb') as f:
        bl_data = bytes(f.read())
        while len(bl_data) < consts.HBOOT_LENGTH:
            bl_data += b'\0'
        if len(bl_data) != consts.HBOOT_LENGTH:
            print("HBoot payload must be 0x%x instead of 0x%x" % (consts.HBOOT_LENGTH, len(bl_data)))
            exit(1)
        bl_enc = crypto.encrypt_verify(bl_data, args.sbk)
        bl_len = len(bl_enc)
        if bl_len > consts.BL_PART_SIZE_MAX:
            print("Bootloader encrypted exceeds 0x%x with 0x%x" % (consts.HBOOT_LENGTH, bl_len))
            exit(1)

    print("BL raw CMAC: %s len: 0x%x" % (utils.to_hex_str(crypto.hash_aes_cmac(bl_data, args.sbk)), bl_len))

    #Load BCT and trim the initial hash
    with open(args.bct, 'rb') as f:
        f.seek(0x10)
        bct_data = bytearray(f.read())
        if len(bct_data) <= 0:
            print("BCT payload is empty!")
            exit(1)

    print("BCT raw CMAC: %s len: 0x%x" % (utils.to_hex_str(crypto.hash_aes_cmac(bl_data, args.sbk)), len(bct_data)))

    #Update BCT with bootloader data
    bl_cmac = crypto.hash_aes_cmac(bl_enc, args.sbk)
    print("BL enc CMAC: %s" % utils.to_hex_str(bl_cmac))
    utils.struct.pack_into("<I", bct_data, 0xf50, bl_len)
    utils.struct.pack_into("B" * 16, bct_data, 0xf60, *bl_cmac)

    #Encrypt BCT        
    bct_enc = crypto.encrypt_verify(bct_data, args.sbk)

    #Hash BCT and save it
    bct_cmac = crypto.hash_aes_cmac(bct_enc, args.sbk)
    bct_enc = bct_cmac + bct_enc
    bct_len = len(bct_enc)
    print("BCT enc CMAC: %s len: 0x%x" % (utils.to_hex_str(bct_cmac), bct_len))
    if bct_len > consts.BCT_PART_SIZE_MAX:
        print("BCT encrypted exceeds 0x%x with 0x%x" % (consts.BCT_PART_SIZE_MAX, bct_len))
        exit(1)

    return bct_enc, bl_enc

def prepare_flasher_payload(hboot_ver):
    header_fmt = "<" + ("I" * 5)
    header_len = utils.struct.calcsize(header_fmt)
    start_addr = utils.get_payload_address(hboot_ver) + header_len
    nl_str = "\n"
    banner_str = "#" * 50 + "\n"

    #Initial state:
    #r7 = Contains this code start address
    #r6 = Contains caller address
    #r5 = Contains magic
    #r4 = Code offset applied at r7
    #r3 = Contains address of payload data
    #r0 = Contains boot mode

    #Register usage:
    #r12 = temporary usage reg
    #r11 = temporary usage reg
    #r10 = pointer to call origin
    #r9 = status code
    #r8 = pointer to start of payload data
    #r7 = current section pointer
    #r6 = check/flash mode
    #r0-5 = scratch regs 
    code_data = bytearray()
    code = asm.compile_arm(thumb=True, code=f"""    
    PayloadExit:
        {asm.code_string("r0", start_addr, code_data, "Exiting code payload")}
        {asm.call(consts.FUNCTION_PRINT_ADDR)}
        pop {asm.br("r8, r9, r10, r11, r12, lr")}
        pop {asm.br("pc")}
        
    RebootPMC:
        {asm.mov32("r2", consts.PMC_ADDR)}
        {asm.mov32("r1", consts.PMC_REBOOT)}
        str     r1, [r2]
        //Not supposed to reach here
        b       PayloadExit
        
    SetBootMode:
        push    {asm.br("r12, lr")}
        {asm.mov32("r12", consts.HBOOT_REASON_ADDR)}
        str r0, [r12]
        pop     {asm.br("r12, pc")}
    
    ErrorOccurred:
        push    {asm.br("r11,r12")}
        //Dump registers for debugging
        {asm.mov32("r12", consts.FAILURE_DUMP_ADDR)}
        mov r11, r12
        stmia   r12!, {asm.br("r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,lr")}
        //Print error msg
        {asm.code_string("r0", start_addr, code_data, "Error occurred! regdump: 0x%x status: 0x%x")}
        mov     r1, r11
        mov     r2, r9
        {asm.call(consts.FUNCTION_PRINT_ADDR)}
        //Set boot mode to recovery
        {asm.mov32("r0", consts.HBOOT_REASON_RECOVERY)}
        bl      SetBootMode
        pop     {asm.br("r11,r12")}
        b       PayloadExit
        
    FlashError:
        //Discard lr pushed by FlashChainStart
        add     sp, #4
        b ErrorOccurred
        
    FlashCheckMagic:
        push    {asm.br("r0,lr")}
        {asm.mov32("r0", consts.FLASHER_MAGIC_VALUE)}
        cmp     r0, r1
        bne     FlashError
        pop     {asm.br("r0,pc")}
        
    FlashCheckDataChecksum:
        push    {asm.br("r0,r1,r2,r3,r4,r5,r6,r7,lr")}
        // r5 = wanted checksum r1 = pointer to data r2 = length of data padded
        mov     r7, r1
        {asm.mov32("r6", consts.CHECKSUM_MASK)}
        //Checksum value
        mov     r4, r6
        //Index
        mov     r3, 0
    FlashCheckDataChecksumLoop:        
        //Load 4 bytes and do some XOR
        ldr     r0, [r7,r3]
        eor     r0, r6
        eor     r0, r3
        
        //Move some data around
        mov     r1, 0xFF
        and     r1, r4, r1
        mov     r1, r1, lsl #24
        mov     r4, r4, lsr #4
        
        //More XOR
        eor     r4, r1
        eor     r4, r0
        
        //Increment and exit if reached all data
        add     r3, 4
        cmp     r3, r2
        blo     FlashCheckDataChecksumLoop
        
        //Print checksum
        push    {asm.br("r0,r1,r2,r3,r4,r5")}
        mov     r1, r4
        mov     r2, r5
        {asm.code_string("r0", start_addr, code_data, nl_str + "Checksum 0x%x expected 0x%x")}
        {asm.call(consts.FUNCTION_PRINT_ADDR)}
        pop     {asm.br("r0,r1,r2,r3,r4,r5")}
        
        //Compare checksum
        cmp     r4, r5
        beq     FlashCheckDataChecksumOK
        add     sp, 0x24
        b       FlashError
        
    FlashCheckDataChecksumOK:
        pop     {asm.br("r0,r1,r2,r3,r4,r5,r6,r7,pc")}
        
    FlashChainExit:
        {asm.code_string("r0", start_addr, code_data, "Exiting flash chain" + nl_str + banner_str + nl_str)}
        {asm.call(consts.FUNCTION_PRINT_ADDR)}
        pop     {asm.br("pc")}
        
    FlashChainStart:
        push    {asm.br("lr")}
        mov     r1, r6
        mov     r2, r8
        {asm.code_string("r0", start_addr, code_data, nl_str + banner_str + "Starting flash chain with mode: 0x%x at 0x%x")}
        {asm.call(consts.FUNCTION_PRINT_ADDR)}
        mov     r9, 0
        mov     r7, r8
        b       FlashChainLoop
        
    FlashChainLoop:
        //Load part_name offset, magic, data_len, part_offset, section_len, data_checksum
        mov     r0, #0xFFFF
        and     r9, r0
        add     r9, 0x1
        ldmia   r7!, {asm.br("r0, r1, r2, r3, r4, r5")}
        add     r9, 0x10000
        
        //Print section
        push    {asm.br("r0,r1,r2,r3,r4,r5")}
        mov     r1, r0
        mov     r3, r4
        {asm.code_string("r0", start_addr, code_data, nl_str + "Next section: part name offset 0x%x len 0x%x section len 0x%x")}
        {asm.call(consts.FUNCTION_PRINT_ADDR)}
        pop     {asm.br("r0,r1,r2,r3,r4,r5")}
        add     r9, 0x10000
        
        //Check section magic
        bl      FlashCheckMagic
        add     r9, 0x10000
        
        //If section is zero then is termination section, also check for errors
        cmp     r4, #0
        beq     FlashChainExit
        cmp     r2, #0
        beq     FlashError
        cmp     r0, #0
        beq     FlashError
        add     r9, 0x10000
        
        //Check end of block section magic
        mov     r1, r7
        add     r1, r4
        ldr     r1, [r1,#4]
        bl      FlashCheckMagic
        add     r9, 0x10000
        
        //Convert string offset to ptr
        add     r0, r8
        
        //Place data_buf pointer to data next to section
        mov     r1, r7
        
        //Check the checksum of data for possible corruption
        cbnz     r6, FlashChainLoopNoChecksum
        bl      FlashCheckDataChecksum
    FlashChainLoopNoChecksum:
        add     r9, 0x10000
        
        //Move r7 to next section
        add     r7, r4

        //Print flashing info
        add     r9, 0x10000
        push    {asm.br("r0,r1,r2,r3,r4,r5")}
        pop     {asm.br("r1,r2,r3")}
        sub     sp, #0xc
        {asm.code_string("r0", start_addr, code_data, "Validated section: part %s at 0x%x len 0x%x", nl=0)}
        {asm.call(consts.FUNCTION_PRINT_ADDR)}
        mov     r1, r7
        mov     r2, r4
        {asm.code_string("r0", start_addr, code_data, " next section at 0x%x len 0x%x")}
        {asm.call(consts.FUNCTION_PRINT_ADDR)}
        pop     {asm.br("r0,r1,r2,r3,r4,r5")}
        
        //Check next section if not in flash mode
        cbz     r6, FlashChainLoopNext        
        
    FlashChainLoopFlash:        
        //Flash!
        add     r9, 0x10000
        push    {asm.br("r7, r8")}
        {asm.call(consts.FUNCTION_WRITE_PARTITION_OFFSET)}
        pop     {asm.br("r7, r8")}
        
        //Print flashing info
        add     r9, 0x10000
        push    {asm.br("r0,r1,r2,r3,r4,r5")}
        mov     r1, r0
        {asm.code_string("r0", start_addr, code_data, "Flashing result: 0x%x")}
        {asm.call(consts.FUNCTION_PRINT_ADDR)}
        pop     {asm.br("r0,r1,r2,r3,r4,r5")}
        
        //Non zero means flashing error
        add     r9, 0x10000
        cmp     r0, #0
        bne     FlashError
        
        //Check next section, until we find a zero len one
    FlashChainLoopNext:
        add     r9, 0x100
        b       FlashChainLoop
        
    entry:
        //r6 contains return adddress
        push    {asm.br("r6")}
        push    {asm.br("r8, r9, r10, r11, r12, lr")}
        mov     r10, r6
        
        //If all is correct r8 will point to same value as r3 for payload pointer
        cmp     r8, r3
        bne     FlashError
        
        //Reset debug info
        {asm.mov32("r4", consts.FAILURE_DUMP_ADDR)}
        mov     r0,#0
        mov     r1,#0
        mov     r2,#0
        mov     r3,#0
        stmia   r4!,{asm.br("r0,r1,r2,r3")}
        stmia   r4!,{asm.br("r0,r1,r2,r3")}
        stmia   r4!,{asm.br("r0,r1,r2,r3")}
        stmia   r4!,{asm.br("r0,r1,r2,r3")}
        
        //Check if we are running on right flasher by checking magic value
        {asm.mov32("r0", consts.BL_LOAD_ADDRESS + consts.FLASHER_MAGIC_ADDR)}
        {asm.mov32("r1", consts.FLASHER_MAGIC_VALUE)}
        ldr     r2, [r0]
        cmp     r2, r1
        bne     RebootPMC
        
        //Check chain first
        mov     r6, 0
        bl      FlashChainStart
    
        //Now flash, as the payload seems OK
        mov     r6, 1
        bl      FlashChainStart
        
        //Finished OK, reboot
        {asm.mov32("r0", consts.HBOOT_REASON_FASTBOOT)}
        bl      SetBootMode
        {asm.call(consts.FUNCTION_REBOOT_ADDR)}
        
        //Execution starts here due to code offset
        mov     r8, pc
        b       entry
    """)

    #Check code section is aligned 
    while (len(code) % 4) != 0:
        code = b"\0" + code

    #Append code data to code
    code = code_data + code

    #Check code section is aligned 
    if (len(code) % 4) != 0:
        raise Exception("Code section not aligned! %d" % len(code))

    #2 Instructions + Thumb mode set, execution starts here
    code_offset = len(code) - 3

    # Where does payload data start
    data_start = start_addr + len(code)

    #Check data section is aligned
    if (data_start % 4) != 0:
        raise Exception("Data section not aligned! %d" % data_start)

    header = utils.struct.pack(header_fmt,
                               0,  #1
                               0,  #2
                               data_start,  #r3
                               code_offset,  #r4
                               consts.FLASHER_MAGIC_VALUE  #r5
                               )

    print("Payload address (with header): 0x%x\nCode address: 0x%x\nData address: 0x%x" % (start_addr, start_addr, data_start))

    return header + code


def package_payload(bct_enc, bl_enc):
    zero_buf = bytearray(4)
    magic_buf = utils.struct.pack("<I", consts.FLASHER_MAGIC_VALUE)
    payload_buf = bytearray()
    bct_len = len(bct_enc)
    bl_len = len(bl_enc)

    #Each section has:
    # 4 bytes int - Pointer to string with partition name (at Nvidia PT)
    # 4 bytes int - Magic
    # 4 bytes int - Length of data to flash
    # 4 bytes int - Offset in partition
    # 4 bytes int - Offset for next section

    #Add BCT section
    bct_part_ptr_addr = len(payload_buf)
    payload_buf += zero_buf
    payload_buf += magic_buf
    payload_buf += utils.struct.pack("<I", bct_len)
    payload_buf += zero_buf
    payload_buf += utils.struct.pack("<I", utils.aligned_len(bct_len))
    payload_buf += utils.struct.pack("<I", utils.checksum(bct_enc))

    payload_buf += bct_enc
    while (len(payload_buf) % 4) != 0:
        payload_buf += b'\0'

    #Add BL section
    bl_part_ptr_addr = len(payload_buf)
    payload_buf += zero_buf
    payload_buf += magic_buf
    payload_buf += utils.struct.pack("<I", bl_len)
    payload_buf += zero_buf
    payload_buf += utils.struct.pack("<I", utils.aligned_len(bl_len))
    payload_buf += utils.struct.pack("<I", utils.checksum(bl_enc))

    payload_buf += bl_enc
    while (len(payload_buf) % 4) != 0:
        payload_buf += b'\0'

    #Add termination section, must contain magic and zero length
    payload_buf += zero_buf
    payload_buf += magic_buf
    payload_buf += zero_buf
    payload_buf += zero_buf
    payload_buf += zero_buf
    payload_buf += zero_buf

    #Add strings and modify pointers to point these
    utils.struct.pack_into("<I", payload_buf, bct_part_ptr_addr, len(payload_buf))
    payload_buf += b"BCT\0"
    utils.struct.pack_into("<I", payload_buf, bl_part_ptr_addr, len(payload_buf))
    payload_buf += b"EBT\0"

    return payload_buf

def verify_flasher(file_flasher):
    with open(file_flasher, 'rb') as f:
        f.seek(consts.FLASHER_MAGIC_ADDR)
        buf = f.read(4)
        value = utils.struct.unpack("<I", buf)[0]
    return value == consts.FLASHER_MAGIC_VALUE


def prepare_flasher(args, hboot_ver):
    with open(args.flasher, 'rb') as f:
        flasher_buf = bytearray(f.read())
    value = utils.struct.unpack_from("<I", flasher_buf, consts.FLASHER_MAGIC_ADDR)[0]
    if value != consts.FLASHER_MAGIC_VALUE:
        print("Provided flasher binary doesn't support acting as flasher!")
        exit(1)

    #Set the address of payload with header
    utils.struct.pack_into("<I", flasher_buf, consts.FLASHER_ADDRESS_ADDR, utils.get_payload_address(hboot_ver))

    return flasher_buf
