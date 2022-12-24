import struct
import consts

def get_fastboot_start(hboot_ver):
    return consts.HBOOT_CONFIG[hboot_ver]["fastboot_start"]

def get_payload_padding(hboot_ver):
    return consts.HBOOT_CONFIG[hboot_ver]["fastboot_padding"]

def get_payload_address(hboot_ver):
    return get_fastboot_start(hboot_ver) + get_payload_padding(hboot_ver)

def aligned_len(input_len):
    while input_len % 4 != 0:
        input_len += 1
    return input_len

def to_hex_str(data):
    text = "0x"
    for b in data:
        b = hex(b)[2:]
        if len(b) == 1: b = "0" + b
        text += b
    return text

def checksum(data):
    if type(data) != bytearray and type(data) != bytes:
        raise Exception("Data not bytes/bytearray")
    if (len(data) % 4) != 0:
        raise Exception("Data not aligned")

    mask = consts.CHECKSUM_MASK
    result = mask
    for i in range(0, len(data), 4):
        value = struct.unpack_from("<I", data, i)[0]
        value = value ^ mask
        value = value ^ i
        resbot = ((result & 0xFF) << 24)
        result = result >> 4
        result = result ^ resbot
        result = result ^ value

    return result

def zip_split(zip_buf, padding_len):
    #Split EOCD from zip and pad the main body to correctly allocate the payload later
    zip_eocd = zip_buf[-consts.ZIP_EOCD_SIZE:]
    zip_buf = zip_buf[:-consts.ZIP_EOCD_SIZE]
    diff = padding_len - len(zip_buf)
    if diff < 0:
        raise Exception("ZIP is 0x%x max is 0x%x" % (len(zip_buf), padding_len))
    elif 0 < diff:
        print("Adding padding of 0x%x for ZIP" % diff)
        zip_buf += bytearray(diff)

    #Check if EOCD is correct
    value = struct.unpack("<I", zip_eocd[0:4])[0]
    if value != consts.ZIP_EOCD_SIGNATURE:
        raise Exception("Generated zip EOCD was not cut correctly!")


    return zip_buf, zip_eocd

def convert_sbk(args):
    sbk_str = args.sbk.lower()
    if sbk_str.startswith("0x"):
        sbk_str = sbk_str[2:]
    if len(sbk_str) != 32:
        print("Please provide 16 bytes long hexadecimal sbk key (32 characters)")
    sbk = []
    for i in range(16):
        by = sbk_str[i*2:i*2+2]
        by = int(by, 16)
        sbk.append(by)
    args.sbk = struct.pack("B"*16, *sbk)
    print("-> Using SBK: 0x" + sbk_str)

"""
This generates a file that can be used to locate the buffer starting address by doing:
READ_ADDR-(READ_VALUE*4) -> BUF_START
"""
def generate_localizer(output, length):
    l = round((length * 1024 * 1024) / 4)
    print("%s generating file with %i ints that spans %i bytes" % (output, l, length))
    with open(output, "wb") as f:
        for x in range(1, l):
            value = struct.pack("<I", x)
            f.write(value)
    print("%s generated", output)
