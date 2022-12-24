import keystone

def compile_arm(code, thumb=False):
    code = code.strip()
    ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB if thumb else keystone.KS_MODE_ARM)
    try:
        binary, _ = ks.asm(code)
        if binary is None:
            error = "No assembler output!"
        else:
            return bytearray(binary)
    except keystone.KsError as e:
        error = e.message

    code_test = ""
    for code_line in code.split("\n"):
        try:
            code_test += code_line.strip() + "\n"
            ks.asm(code_test)
        except keystone.KsError:
            break

    if 0 == len(code_test):
        code_test = "Unknown line"
    else:
        code_test += "^^^^^^^^^^^^^^^^^^^^^^^^"
    
    import traceback
    print("\n>>> Keystone assembler error <<<")
    traceback.print_stack()
    print("\nAttempted code:\n%s\n%s" % (code_test, error))
    exit(1)


def mov32(register, constant):
    constant_l = "0x%x" % (constant & 0xFFFF)
    constant_h = "0x%x" % ((constant & 0xFFFF0000) >> 16)
    return f"movw {register}, #{constant_l};\n\t\tmovt {register}, #{constant_h};"


def call(addr, r0=None, r1=None, r2=None, r3=None):
    code = ""
    if r0 is not None:
        code += f"""mov r0, {r0};\n\t\t"""
    if r1 is not None:
        code += f"""mov r1, {r1};\n\t\t"""
    if r2 is not None:
        code += f"""mov r2, {r2};\n\t\t"""
    if r3 is not None:
        code += f"""mov r3, {r3};\n\t\t"""
    code += f"""
        push {br("r12")};
        {mov32("r12", addr)};
        blx r12;
        pop {br("r12")};
    """
    return code


def br(text):
    return "{" + text + "}"

def code_data(register, start_addr, buf, data):
    addr = len(buf)
    buf += data
    while (len(buf) % 4) != 0:
        buf += b'\0'
    return mov32(register, start_addr + addr)

def code_string(register, start_addr, buf, text, nl=1):
    if 0 < nl and not text.endswith("\n"):
        text += "\n" * nl
    if not text.endswith("\0"):
        text += "\0"
    text = bytearray(text.encode("ascii"))
    return code_data(register, start_addr, buf, text)
