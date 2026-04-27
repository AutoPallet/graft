import serial, sys, time

# ESP32-S3 native-USB-JTAG reset sequence.
#  - Host DTR asserted → device drives IO0 low (bootloader strapping)
#  - Host RTS asserted → device drives CHIP_PU low (reset)
# Want: assert reset, RELEASE reset with DTR de-asserted, then
# the chip boots from flash with IO0 high. Don't pulse DTR active in
# the middle.
s = serial.Serial("/dev/ttyACM0", 115200, timeout=8)
s.dtr = True   # IO0 high (inverted polarity for esp32s3 native-USB)
s.rts = False  # reset asserted (inverted)
time.sleep(0.1)
s.dtr = True   # IO0 still high
s.rts = True   # release reset → flash boot
time.sleep(0.1)

target = sys.argv[1].encode() if len(sys.argv) > 1 else b"tick="
n = int(sys.argv[2]) if len(sys.argv) > 2 else 3
data = b""
end = time.time() + 12
while time.time() < end:
    chunk = s.read(2048)
    if chunk:
        data += chunk
    if data.count(target) >= n:
        break
print(data.decode("utf-8", errors="replace"))
