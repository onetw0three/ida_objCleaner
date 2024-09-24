from ida_hexrays import *
import ida_idaapi
import ida_idp
import ida_funcs
import ida_ua
import ida_kernwin
import re

OBJCLEANER = None
OBJCLEANER_TOGGLE_ON = False # off by default
OBJCLEANER_HOTKEY = "Ctrl-Alt-e"

# Functions with prototype: id func(id)
MOVES_FUNC = [
    "_objc_retainAutorelease",
    "_objc_retainAutoreleasedReturnValue",
    "_objc_retainAutoreleaseReturnValue",
    "_objc_unsafeClaimAutoreleasedReturnValue",
    "_objc_claimAutoreleasedReturnValue",
    "_objc_autoreleaseReturnValue",
    "_objc_autorelease",
    "_objc_retainBlock"
]
MOV_REG_VARIANTS = ["_objc_retain"]

# Functions with prototypes: void func(id)
HIDE_FUNCS = ["_objc_release"]


# =======================================================
REGEX_SUFFIX = "(_(\d)+)?$"
REGEX_REG_GROUP = "(_(x\d+))?"

# handles suffixed names like _objc_claimAutoreleasedReturnValue_123, in DSCs
def check_name_variants(name: str, suffix: str):
    # print(name, suffix, re.match(f"{suffix}{REGEX_SUFFIX}", name))
    return True if re.match(f"{suffix}{REGEX_SUFFIX}", name) else False

# Similar to above but handle register variants like _objc_retain_x19_123
def check_name_reg_variants(name: str, suffix: str):
    if matched := re.match(f"{suffix}{REGEX_REG_GROUP}{REGEX_SUFFIX}", name):
        reg = matched.group(2) # gets the register name
        return reg if reg else "x0" 
    return False

def get_call_target_name(callsite_ea: int):
    insn = ida_ua.insn_t()
    length = ida_ua.decode_insn(insn, callsite_ea)
    return ida_funcs.get_func_name(insn.Op1.addr)

# Taken from https://github.com/P4nda0s/IDABeautify/blob/main/Beautify.py#L10
def parse_reg(reg_name):
    reg_info = ida_idp.reg_info_t()
    if not ida_idp.parse_reg_name(reg_info, reg_name):
        print("Bad reg name:", reg_name)
        return None, None
    mreg = reg2mreg(reg_info.reg)
    if mreg == -1:
        print(f"Failed to convert {reg_name} to microregister")
        return None, None
    return mreg, reg_info.size

def create_mov_reg_reg(ea, src_reg: str, dst_reg: str):
    m = minsn_t(ea)
    m.opcode = m_mov
    m.l.make_reg(*parse_reg(src_reg))
    m.d.make_reg(*parse_reg(dst_reg))
    m.iprops |= IPROP_ASSERT
    return m

# =======================================================

class objcleaner_visitor_t(minsn_visitor_t):
    cnt = 0
    def __init__(self):
        minsn_visitor_t.__init__(self)

    def _need_hide(self, target_name: str):
        for hide_func in HIDE_FUNCS:
            if check_name_variants(target_name, hide_func) or check_name_reg_variants(target_name, hide_func):
                return True
        return False
    
    def _need_mov(self, target_name:str):
        # Changes a call id func@<X0>(id@<X0>) to a 'mov x0, x0'
        for mov_func in MOVES_FUNC:
            if check_name_variants(target_name, mov_func):
                return "x0"

        # Changes a call id func@<X0>(id@<X?>) to a 'mov x0, x?'
        for mov_reg_func in MOV_REG_VARIANTS:
            if reg := check_name_reg_variants(target_name, mov_reg_func):
                return reg

        return None
    
    def visit_minsn(self):
        ins = self.curins
        if ins.opcode != m_call: 
            return 0
        
        # Resolve callee's name 
        target_name = None
        if ins.l.t == mop_v: # global type
            target_name = ida_funcs.get_func_name(ins.l.g)
        elif ins.l.t == mop_h: # helper function
            target_name = get_call_target_name(ins.ea)
    
        if target_name: 
            if dst_reg := self._need_mov(target_name):
                # print(f"[+] Replacing movs @ {hex(ins.ea)}: {dst_reg}")
                ins.swap(create_mov_reg_reg(ins.ea, dst_reg, "x0"))
                self.cnt = self.cnt + 1

            elif self._need_hide(target_name):
                # print(f"[+] Hiding call @ {hex(ins.ea)}")
                ins._make_nop()
                self.cnt = self.cnt + 1
        return 0

class objcleaner_optinsn_t(optinsn_t):
    def __init__(self):
        optinsn_t.__init__(self)

    def func(self, blk, ins, optflags):
        # Only process after IDA lifts the call, so that it does not mess up the callee's args
        if blk.mba.maturity > MMAT_CALLS: return 0

        opt = objcleaner_visitor_t()
        ins.for_all_insns(opt)
        if opt.cnt != 0:
            blk.mba.verify(True) 
        return opt.cnt

class objcleaner_plugin_t(ida_idaapi.plugin_t):
    flags = 0  # normal plugin
    wanted_name = "Show/Hide ObjC ARC runtime"
    wanted_hotkey = OBJCLEANER_HOTKEY
    comment = "Show/Hide ObjC ARC runtime function calls"
    help = ""

    def init(self):
        if init_hexrays_plugin():
            print("Installed Obj-C Runtime Cleaner")
            return ida_idaapi.PLUGIN_KEEP
    def term(self):
        if OBJCLEANER_TOGGLE_ON:
            self.optimizer.remove()
    def run(self, arg):
        toggle_plugin()


def toggle_plugin():
    global OBJCLEANER_TOGGLE_ON

    if not OBJCLEANER_TOGGLE_ON:
        OBJCLEANER.optimizer = objcleaner_optinsn_t()
        OBJCLEANER.optimizer.install()
        print("[+] ObjCleaner: optimiser on")
    else:
        OBJCLEANER.optimizer.remove()
        print("[+] ObjCleaner: optimiser off")
    OBJCLEANER_TOGGLE_ON = not OBJCLEANER_TOGGLE_ON

def PLUGIN_ENTRY():
    global OBJCLEANER
    OBJCLEANER = objcleaner_plugin_t()
    return OBJCLEANER
