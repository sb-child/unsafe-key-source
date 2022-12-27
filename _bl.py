import serial
import time

def main():
    # 57600 8E1
    s = serial.Serial("/dev/ttyUSB0", 57600, rtscts=True, dsrdtr=True)
    s.setRTS(True)
    s.setDTR(True)
    time.sleep(0.3)
    s.setRTS(False)
    time.sleep(0.3)
    # s.setDTR(False)
    s.setDTR(True)
    time.sleep(0.3)
    s.setRTS(False)
    s.setDTR(False)
    s.close()

if __name__ == '__main__':
    main()
