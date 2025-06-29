Out-of-tree Rockchip RK915 Wi-Fi driver for mainline Linux
=============

Origins
-------------
This is a port of BSP driver obtained from device vendor.  
See [original patch](https://github.com/stolen/rk915/blob/main/docs/0001-rk915.patch) for reference.  

As I'm a developer at [Rocknix](https://rocknix.org/), I needed this chip to work with
mainline Linux (6.12.29 at the moment). So, I tried to port the driver.

How to use
-------------
  1. patch your kernel with [mainline patch](https://github.com/stolen/rk915/blob/main/docs/mainline-linux-hacks-for-rk915.patch)
  2. add [needed sections](https://github.com/stolen/rk915/blob/main/docs/mainline-linux-dts-example.dtsi) to your device tree
  3. build this source as an out-of-tree module `make V=1 -C $(kernel_path) M=${PKG_BUILD} ... CONFIG_RK915=m`
  4. copy files from `firmware` dir to `/lib/firmware` (the driver needs these)
  5. `insmod rk915.ko`

Status
-------------
The driver is not usable yet.  
Known issues:
  * Soon after association chip disconnects from network
  * Unloading the driver will likely stall your system
