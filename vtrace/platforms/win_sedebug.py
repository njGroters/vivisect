#!/usr/bin/env python

import sys

from vtrace.platforms.win32 import *

import logging
logger = logging.getLogger(__name__)


PRIV_NAMES = (
        b'SeBackupPrivilege',
        b'SeDebugPrivilege',
        b'SeSecurityPrivilege',
)


def LookupPrivValue(name, remote_server=None):
    dbgluid = LUID()
    if not advapi32.LookupPrivilegeValueA(0, name, addressof(dbgluid)):
        logger.warning("LookupPrivilegeValue Failed: %d", kernel32.GetLastError())
        return -1
    return dbgluid.LowPart | (dbgluid.HighPart<<32)

def LookupPrivName(privnum, remote_server=None):
    luid = LUID()
    luid.LowPart = privnum & 0xffffffff
    luid.HighPart = privnum >> 32

    cchName = ctypes.c_int()
    if not advapi32.LookupPrivilegeNameA(None, addressof(luid), 0, addressof(cchName)):
        err = kernel32.GetLastError()
        if err != 122:  # insufficient buffer size
            logger.warning("LookupPrivilegeName Failed (getting msg size): %d", kernel32.GetLastError())

    privname = ctypes.create_string_buffer(cchName.value+1)
    if not advapi32.LookupPrivilegeNameA(None, addressof(luid), byref(privname), addressof(cchName)):
        logger.warning("LookupPrivilegeName Failed: %d", kernel32.GetLastError())
        return -1
    if not cchName:
        return -1
    return privname.value

def GetTokenPrivInfo(tok):
    retlen = c_int()
    advapi32.GetTokenInformation(tok, TokenPrivileges, 0, 0, addressof(retlen))
    
    outstr = create_string_buffer(retlen.value + 1)
    advapi32.GetTokenInformation(tok, TokenPrivileges, addressof(outstr), retlen.value, addressof(retlen))
    
    count = struct.unpack_from("<I", outstr.raw, 0)[0]
    vals = []
    for x in range(count):
        vals.append(struct.unpack_from("<QI", outstr.raw, 4 + (12*x)))
    return vals

def OpenProcToken(flags=TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY):
    tok = HANDLE(0)
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), flags, addressof(tok)):
        logger.warning("Failed to Open Process Token: %d", kernel32.GetLastError())
    return tok

def AdjustTokenPrivs(tok, disableall=False, new_proc_privs=[]):
    privlen = len(new_proc_privs)
    prevstate = create_string_buffer(4+(12*privlen))
    retsize = c_int()
    
    newstate = struct.pack(b"<I", privlen)
    for x in range(privlen):
        newstate += struct.pack(b"<QI", *new_proc_privs[x])
    newstate_c = create_string_buffer(newstate)
    
    retval = advapi32.AdjustTokenPrivileges(tok, disableall, addressof(newstate_c), len(prevstate), addressof(prevstate), addressof(retsize))

    out = []
    if retsize.value > 0:
        changedct = struct.unpack_from("<I", prevstate.raw, 0)[0]
        for x in range(changedct):
            out.append(struct.unpack_from("<QI", prevstate.raw, 4+(12*x)))
            
    if not retval:
        print(kernel32.GetLastError())

    return out
    
def enable_privs(remote_server=None, priv_names=PRIV_NAMES):
    priv_ids = sorted(LookupPrivValue(e, remote_server) for e in priv_names)

    logger.debug("Privileges to be enabled IDs:")
    for privnum in priv_ids:
        privname = LookupPrivName(privnum)
        logger.debug("\t%s (%d)", privname, privnum)

    tok = OpenProcToken()
    
    proc_privs = GetTokenPrivInfo(tok)
    logger.debug("Existing process privileges:")
    prev_privs = {}
    for privnum, privval in proc_privs:
        prev_privs[privnum] = privval
        logger.debug("\t%s (%d): %r", LookupPrivName(privnum), privnum, privval)
        
    new_proc_privs = []
    need_change = False
    for proc_priv in proc_privs:
        if proc_priv[0] in priv_ids:
            logger.debug("Checking privilege %s (%d)", LookupPrivName(proc_priv[0]), proc_priv[0])
            if proc_priv[1] != SE_PRIVILEGE_ENABLED:
                need_change = True
            new_proc_privs.append((proc_priv[0], SE_PRIVILEGE_ENABLED))
        else:
            new_proc_privs.append(proc_priv)
    logger.debug("New process privileges:")
    new_privs = {}
    for privnum, privval in new_proc_privs:
        logger.debug("\t%s (%d): %r", LookupPrivName(privnum), privnum, privval)
        new_privs[privnum] = privval
        
    if need_change:
        modif_privs = AdjustTokenPrivs(tok, False, new_proc_privs)
        res = kernel32.GetLastError()
        logger.debug("Changed privileges:") # Changed ones
        for privnum, privval in modif_privs:
            prev_priv = new_privs.get(privnum)
            logger.debug("\t%s (%d): %r -> %r", LookupPrivName(privnum), privnum, privval, prev_priv)
        
        if res != 0:
            logger.warning("Error (partial) setting privileges: %r", res)
    else:
        logger.debug("Already set")
    #advapi32.GetTokenInformation(tok, advapi32.TokenPrivileges)  # To compare with proc_privs
    kernel32.CloseHandle(tok)


def main(*argv):
    enable_privs()


if __name__ == "__main__":
    print("Python {:s} {:03d}bit on {:s}\n".format(" ".join(elem.strip() for elem in sys.version.split("\n")),
                                                   64 if sys.maxsize > 0x100000000 else 32, sys.platform))
    import envi.common as ecmn
    ecmn.initLogging(logger, ecmn.SHITE)
    rc = main(*sys.argv[1:])
    print("\nDone.")
    sys.exit(rc)
