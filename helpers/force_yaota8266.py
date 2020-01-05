"""
    Reset and force start the OTA Server on device
    by save yaota8266 magic word to RTC RAM.
"""
import machine

if __name__ == '__main__':
    machine.RTC().memory('yaotaota')
    machine.reset()
