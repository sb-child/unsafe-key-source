import serial
import time

def main():
    # 57600 8E1
    s = serial.Serial("/dev/ttyUSB0", 57600, rtscts=True, dsrdtr=True)
    # into bootloader mode
    s.setRTS(True)
    s.setDTR(True)
    time.sleep(0.1)
    # set BOOT0 to low
    s.setDTR(False)
    time.sleep(0.1)
    # reset
    s.setRTS(False)
    time.sleep(0.1)
    s.setRTS(True)
    s.close()

if __name__ == '__main__':
    main()
