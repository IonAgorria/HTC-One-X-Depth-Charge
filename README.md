# HTC One X - Depth Charge HBoot exploit

HBoot Exploit implementation for Tegra 3 variant of HTC One X (not X+, but is probably vulnerable too).

Exploit works by overflowing a heap buffer used to store USB config descriptor during USB enumeration and smashing a pointer to an address to memory region previously written via fastboot flash to inject a custom thread into executing threads pool. The device has to pretend to be a proper USB mass storage device for this to work as the smashed pointer is used once USB code has finished successfully.

Current payload will flash a patched HBoot (changes noted below) that disables security checks and allow full unrestricted access to device MMC.

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT.

By using this exploit, you acknowledge that you are intentionally turning off the device's security features. While some potential brick situations have been restricted, the author is not liable for any consequence or warranty void and will not provide any support regarding the usage or results of this exploit.

## Why

As part of group [PostmarketOS on Tegra](https://t.me/pmos_on_tf) that intends to port U-Boot and mainline Linux to all possible Tegra devices, we wanted to port it to HOX.

This device was the only one where PMC trick to enter RCM/APX wouldn't work, there is no special hardware button combo to access RCM/APX and BCT/bootloader region was locked down via eMMC write group protection so no way to flash any custom bootloader.

I took this as an interesting opportunity and challenge to learn about reverse engineering and exploitation of an old ARM device with goal to help installing open source counterparts instead of vendor bootloader and OS.

## Patched HBoot differences

- Disabled security check to avoid locked down state
- S-OFF hardcoded
- writesecureflag removed to avoid bricks in stock hboot
- writepid removed
- Enabled entering RCM/APX using PMC trick as other Tegra devices
- fastboot oem rcm added to enter RCM/APX mode
- vol-up + vol-down or vol-up + pwr to enter RCM/APX
- vol-up to enter recovery
- vol-down to enter fastboot
- fastboot flash diag to run any binary from RAM including another hboot
- fastboot flash hboot to flash bootloader binary (DANGEROUS)
- Special code to act as payload flasher when used in DIAG inside exploit

## Content

- depthcharge_tinyusb: Contains a modified TinyUSB MSC device example to trigger exploit by sending a specially crafted descriptor.
- depthcharge_generator: Script to generate payload that will be sent using fastboot, pre-assembled payloads are provided in binaries.
- binaries/payload_*_*_normal.bin: Payload to be sent via fastboot, please choose one matching your phone HBoot version, you usually only need this.
- binaries/bct_*_enc.bin binaries/ebt_*_enc.bin: Encrypted patched hboot to be flashed via RCM/APX in case something goes wrong, or you have access to RCM.
- binaries/hboot_*_patched_*.bin: Patched non encrypted hboot without signature, can be also used as flasher when assembling payload.

## Preparation

- Backup anything important from your phone, as anything can go deeply wrong when messing with bootloader.
- Compile "depthcharge_tinyusb" firmware for [TinyUSB](https://docs.tinyusb.org/) compatible device and flash firmware on the device, such as rp2040
- Select payload in binaries for your HBoot such as payload_1.72.0000_108_normal.bin if your phone hboot is 1.72

## Usage

- Put HBoot in fastboot menu by powering up with vol down pressed and switching to fastboot menu with power button
- fastboot flash noexist payload_$YOURHBOOTVERSION_108_normal.bin, is okay if fails as long as Sending part was OKAY (we want to write it to RAM, not flash it)
```
Sending 'noexist' (20487 KB)   OKAY [  2.709s]
Writing 'noexist'              FAILED (remote: 'not allowed')
```
- Plug Y-OTG with power cable unplugged and your TinyUSB device connected
- HBoot menu should now show "FASTBOOT" instead of "FASTBOOT USB" as USB power is not connected
- Plug the power cable for Y-OTG and press phone power button to switch HBoot from fastboot to hboot menu at same time
- Follow screen texts, it should say "Please unplug USB" at the end
- Unplug USB cable from phone
- Wait for reboot and don't plug any USB to phone until finishes rebooting to new bootloader (booting flasher with USB plugged will cause it to hang)
- You should see patched HBoot with S-OFF on reboot

USB plugging timing is difficult to get right or exploit may have crashed so several attempts (up to 3 or 4) may be required until screen shows text about flashing.

If phone gets stuck for a minute please long press power button and retry whole process from start again.
Tegra SoC may get hot when it hangs so is recommended to not wait too much.

## Something went wrong

In case the flashing went wrong and your device is in RCM/APX mode, you can manually flash the patched hboot using bct_108_enc.bin and ebt_108_enc.bin
with Fusee-Geelee for Tegra 3 https://github.com/tofurky/tegra30_debrick/ or using the prepackaged NvFlash for HOX

In rare case where device doesn't boot into RCM/APX because BCT signature is OK but bootloader is not functional, you can trigger APX mode by grounding this pin indicated at [apx.png](/images/apx.png) to ground (any screw hole pad in board or USB connector are grounded)

## Supported HBoot versions

At this moment payloads for 1.36 and 1.72 hboot versions are generated, for adding new versions please consult HBOOT_CONFIG in depthcharge_generator/consts.py.
It contains per version specific addresses required to patch/call.

## Payload modes

In case you can't use tinyusb or prefer to use a different device with custom USB Config Desc and phone crashes before reaching "Please unplug USB" even when 
pointer is actually smashed correctly you may try immediate mode payload which attempts to stop main thread execution and immediately running payload as soon
as exploit is triggered, due to the hackiness and need to unplug USB manually (a 10 seconds delay is added to give time).

To use payload modes other than "normal" you should know really what you are doing.

## UART

HOX has Tegra 3 UART A TX [uarta_tx.png](/images/uarta_tx.png) and RX [uarta_rx.png](/images/uarta_rx.png) pads in CPU side of board.

Bootloader uses UART A by default to send messages and was valuable for debugging and exploring bootloader.

## Disclosure

- 2022/07-2022/08: Discovery and proof of concept
- 2022/08/10: Reported to HTC
- 2022/08/26: HTC acknowledged to receive report

## Licence

depthcharge_generator and depthcharge_tinyusb are released under GPL v3
