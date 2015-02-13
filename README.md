Beeper
======

What is it?
-----------

A tiny Linux command-line tool to make WLAN frames audible.


How to use it?
--------------

    beeper <options> <source MAC address>
     -I <device>    device to use (mandatory, device must be in monitor mode)
     -c <count>     expected frames/second to estimate PRR (optional, default = 10)

### Example

    $ sudo iw phy phy0 interface add mon0 type monitor
    $ sudo ifconfig mon0 up
    $ sudo iw mon0 set channel 6
    $ sudo ./beeper -I mon0 00:11:22:33:44:55

This will set-up a monitor-mode WLAN interface and configure it to listen on
channel 6. Beeper is then configured to listen (beep) for beacon frames from an
access point with MAC address 00:11:22:33:44:55. Be sure to stop other programs
from fiddeling with your WLAN interface (e.g. NetworkManager).


Limitations
-----------

This tool was kludged tother in one afternoon. Bear with me ;-) and report bugs
to till <dot> wollenberg <at> uni-rostock <dot> de.

Beeper works only with WLAN drivers which use the mac80211 stack and support
monitor mode plus Radtiotap headers. It also uses the ancient KIOCSOUND ioctl()
to beep the PC speaker. This will not work on systems lacking such a device and
may also fail on modern systems. Using ALSA or PulseAudio for sound output is
on my list.
