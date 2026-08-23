#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
=====================================================================
 Keygen for "Easy Keygen Crackme" by plikan (crackmes.one)
 Reversed from Easy_Keygen_Crackme.exe (.NET / IL)

 Pipeline (verified against IL):
   MachineGuid  = HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
                  (Registry64 view; "" on failure)
   VolSerial    = GetVolumeInformation("C:\\") -> uint.ToString("X")
                  (uppercase hex, no zero padding; "" on failure)
   PcHash       = SHA256_hex( MachineGuid + VolSerial )            [lowercase]
   Password     = SHA256_hex( PcHash + "plikan" )                  [salt]
   Final512     = SHA512_hex( Password ).ToUpper()                 [uppercase]
   Key          = Format("{0}-{1}-{2}-{3}-{4}",
                        Final512[0:5],[5:10],[10:15],[15:20],[20:25])

 Checker: String.Equals(input.Replace(" ","").Trim(), XYI,
                          StringComparison.OrdinalIgnoreCase)  -> case-insensitive.
 Dead code (decoys, no xrefs): GeneratePasswordFromCustomHash,
   GenerateKeyFromCustomHash ("INVALID-HASH-LENGTH"), GetFinalStrongHashCustom.
 No patching needed - this computes the real key.
=====================================================================
"""
import hashlib
import sys

def get_machine_guid():
    """Replicates gwaog4a8gpjsr89r5::GetMachineGuid()"""
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\Microsoft\Cryptography",
                           0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        val, _ = winreg.QueryValueEx(k, "MachineGuid")
        return val if val is not None else ""
    except Exception:
        return ""

def get_volume_serial():
    """Replicates gwaog4a8gpjsr89r5::GetVolumeSerial() - C# 'X' format"""
    try:
        import ctypes
        from ctypes import wintypes
        serial = wintypes.DWORD()
        if ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p("C:\\"), None, 0,
                ctypes.byref(serial), None, None, None, 0):
            return format(serial.value, 'X')
    except Exception:
        pass
    return ""

def sha256_hex(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def sha512_hex(s):
    return hashlib.sha512(s.encode('utf-8')).hexdigest()

def keygen(machine_guid=None, volume_serial=None):
    if machine_guid is None:
        machine_guid = get_machine_guid()
    if volume_serial is None:
        volume_serial = get_volume_serial()

    pc_hash  = sha256_hex(machine_guid + volume_serial)      # GetPcHash()
    password = sha256_hex(pc_hash + "plikan")                # GeneratePassword()
    final512 = sha512_hex(password).upper()                  # GetFinalStrongHash()

    # GenerateKey(): "{0}-{1}-{2}-{3}-{4}" over 5x5 chars
    parts = []
    for i in range(0, 25, 5):
        parts.append(final512[i:i+5])
    return "-".join(parts), pc_hash, password, final512

if __name__ == "__main__":
    mg, vs = get_machine_guid(), get_volume_serial()
    print(f"[*] MachineGuid   : {mg}")
    print(f"[*] VolumeSerial  : {vs}")
    key, pc, pw, f512 = keygen(mg, vs)
    print(f"[*] PcHash        : {pc}")
    print(f"[*] Password      : {pw}")
    print(f"[*] SHA512 (upper): {f512}")
    print()
    print("=" * 40)
    print(f"  ACTIVATION KEY:  {key}")
    print("=" * 40)
