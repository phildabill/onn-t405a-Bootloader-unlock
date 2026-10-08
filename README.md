# onn. 11" Core Tablet (2026) — T405A Bootloader Unlock

Bootloader unlock procedure for the **2026 onn. 11" Core Tablet**, also identified as:

```text
Device:       onn11Core
Board:        T405A
Retail model: 36018341
SoC:          MediaTek Helio G99 / MT8781 family
Android:      Android 16
```

The normal Android bootloader unlock mechanism is disabled on this device.

The method documented here uses a stack overflow in the MediaTek **LK Fastboot** `oem erase` handler to change the bootloader lock state.

This procedure was successfully tested on a real T405A.

The underlying LK vulnerability and payload are documented on the Nura Wiki:

**https://wiki.nura.eco/wiki/Onn_11_Core_Tablet_%28onn-t405a%29**

---

## Tested firmware

The tablet used for testing reported:

```text
onn/onn11Core_CA/onn11Core:16/BP2A.250605.031.A3/1786540660:user/release-keys
```

This guide only documents what was actually tested on that device and firmware.

---

# Warning

This is **not** Android's normal bootloader unlock procedure.

The exploit deliberately triggers a stack overflow inside LK and changes the bootloader lock state stored in `seccfg`.

There is a real possibility of making the tablet unbootable.

The exploit also bypasses the normal userdata wipe performed by a standard bootloader unlock. Because the encryption state no longer matches afterward, Android userdata may become inaccessible and a factory reset may be required.

**Do not repeatedly send the exploit payload.**

Do not use this procedure on another onn tablet simply because it also uses a MediaTek SoC.

This guide applies specifically to:

```text
onn. 11" Core Tablet (2026)
onn11Core
T405A
```

---

# Prerequisites

The successful procedure was performed on Windows using:

- Android Platform Tools
  - `adb.exe`
  - `fastboot.exe`
- Python 3.14
- MTKClient
- [`onn_t405a_fastboot_raw_v2.py`](onn_t405a_fastboot_raw_v2.py)

The Python utility uses MTKClient's USB backend, so it should be run from the root directory of your MTKClient installation.

The working test environment used a directory similar to:

```text
I:\Downloads\test\mtkclient
```

Python was invoked using:

```cmd
py -3.14
```

USB debugging must already be enabled on the tablet.

---

# 1. Enter LK Fastboot

With Android running:

```cmd
adb reboot bootloader
```

Check that Windows sees the tablet:

```cmd
fastboot devices
```

You should receive output similar to:

```text
<device-id>    fastboot
```

If the tablet appears, the Fastboot USB driver is working.

On the tested Windows installation, Windows Update installed the required Fastboot driver.

---

# 2. Confirm that the bootloader is locked

Run:

```cmd
fastboot getvar unlocked
```

Before the exploit, the tested tablet returned:

```text
unlocked: no
```

Also run:

```cmd
fastboot flashing get_unlock_ability
```

The tested tablet returned:

```text
(bootloader) unlock_ability is false

OKAY
```

The tested tablet also had **no OEM Unlocking option in Developer Options**.

Therefore the normal Android bootloader unlock procedure was not available.

---

# 3. How the exploit works

The LK bootloader's `oem erase` handler copies the supplied partition argument into a **16-byte stack buffer without bounds checking**.

The saved ARM64 link register, `x30`, is located at offset:

```text
+0x18
```

The exploit payload consists of:

```text
oem erase
+
24 x "A"
+
f8 83 f8 50
```

The complete payload is:

```text
38 bytes
```

The final four bytes partially overwrite the saved return address.

The original return address documented for this exploit is:

```text
0xffff000050f08560
```

After the partial overwrite:

```text
0xffff000050f883f8
```

Execution then enters the LK code path that writes:

```text
state = 3
```

to the bootloader lock-state storage in `seccfg`.

The actual payload used by the Python utility is:

```python
OVERFLOW = b"oem erase " + b"A" * 24 + bytes.fromhex("f8 83 f8 50")
```

The raw payload is sent directly over USB rather than through the normal `fastboot` command-line utility.

---

# 4. Python utility

The repository contains:

```text
onn_t405a_fastboot_raw_v2.py
```

The utility has three operating modes:

```text
--probe
--unlock
--show-payload
```

### `--probe`

Performs a read-only check of the LK Fastboot USB interface.

It does **not** send the exploit.

### `--unlock`

Verifies that the device is in LK Fastboot and then sends the exploit payload once.

### `--show-payload`

Displays the exploit payload without opening the USB device.

---

# 5. Run the read-only probe first

Place:

```text
onn_t405a_fastboot_raw_v2.py
```

in the root of the MTKClient directory.

Then run:

```cmd
py -3.14 onn_t405a_fastboot_raw_v2.py --probe
```

On the tested tablet, a successful probe produced:

```text
Waiting up to 60 seconds for LK fastboot USB 0E8D:201C (disconnect/reconnect if needed)...
No active USB configuration ([Errno None] Configuration not set); selecting 1...
USB configuration activated: 1
Found 0E8D:201C, interface 0, BULK OUT 0x01, BULK IN 0x81
getvar:is-userspace: b'OKAYno'
getvar:unlocked: b'OKAYno'
PROBE COMPLETE; no exploit sent and no flash changes requested.
```

The important result is:

```text
getvar:is-userspace: b'OKAYno'
```

This confirms that the USB connection is talking to **LK Fastboot**, not Android Fastbootd.

The second important result is:

```text
getvar:unlocked: b'OKAYno'
```

which confirms that the bootloader is currently locked.

**Do not continue with the exploit unless the probe succeeds.**

---

# 6. Unlock the bootloader

Run:

```cmd
py -3.14 onn_t405a_fastboot_raw_v2.py --unlock
```

The program displays a warning and requires the exact confirmation:

```text
UNLOCK T405A
```

before sending anything.

After confirmation, the program verifies the Fastboot interface again and sends the documented **38-byte payload exactly once**.

On the tested tablet, the exploit resulted in the device entering the expected **orange boot state**.

If the USB connection disappears or the tablet reboots after sending the payload, **do not immediately send the exploit again**.

Check the tablet first.

---

# 7. Verify the unlock

Enter Fastboot again if necessary.

Run:

```cmd
fastboot getvar unlocked
```

The expected result after a successful unlock is:

```text
unlocked: yes
```

Once Android is available, the boot state can also be checked using:

```cmd
adb shell getprop ro.boot.flash.locked
adb shell getprop ro.boot.verifiedbootstate
```

The expected unlocked state is:

```text
0
orange
```

---

# 8. Factory reset

Because this exploit directly changes the bootloader lock state rather than using Android's normal unlock process, the existing userdata encryption state may no longer be usable.

If Android cannot boot normally or recovery reports a userdata/encryption problem, perform:

```text
Factory data reset
```

from the tablet's recovery environment.

---

# USB IDs observed during testing

The following MediaTek USB IDs were observed while working with the T405A:

```text
0E8D:201C = LK Fastboot
0E8D:2000 = MediaTek preloader
0E8D:20FF = HID mode observed during USB mode changes
```

The unlock utility intentionally targets only:

```text
0E8D:201C
```

Before sending the exploit, it also issues:

```text
getvar:is-userspace
```

If the response indicates userspace Fastboot, the script stops because the tablet is in **Fastbootd rather than LK Fastboot**.

---

# Result

On the tested:

```text
onn. 11" Core Tablet (2026)
onn11Core
T405A
```

the procedure successfully changed the bootloader from:

```text
unlocked: no
unlock_ability is false
```

to an **unlocked / orange boot state**.

Normal Fastboot flashing operations were available afterward.

---

# Credits

The underlying LK vulnerability, analysis, addresses, and exploit payload are documented on the:

### Nura Wiki — onn. 11 Core Tablet (onn-t405a)

https://wiki.nura.eco/wiki/Onn_11_Core_Tablet_%28onn-t405a%29

The Python utility in this repository was created to transmit the documented payload through the Windows/MTKClient USB backend.

It was successfully used on a real T405A.

---

# Scope

This repository documents only the procedure actually tested on:

```text
T405A / onn11Core
```

It should **not** be assumed to work on:

- other onn tablets
- other T-series boards
- other MediaTek devices
- different LK builds

The exploit depends on device-specific LK code and addresses.
