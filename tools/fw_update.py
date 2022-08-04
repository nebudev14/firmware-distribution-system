#!/usr/bin/env python
"""
Firmware Updater Tool
A frame consists of two sections:
1. Two bytes for the length of the data section
2. A data section of length defined in the length section

x represents some number of padding depends on the how large the encoding of firmware is.

[ 16 Tag ] | [ 16 Nonce ] | [ 64 ECC key ] | [ 2 bytes Version ] | [ 2 bytes Firmware Length ] | [ x Firmware ] | [ x Message ] | [ 1 Null Byte ] | [ x Padding ] | [ 64 Padding ] 

In our case, the data is from one line of the Intel Hex formated .hex file
We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a zero
"""

import argparse
import struct
import time

from serial import Serial

RESP_OK = b'\x00'
FRAME_SIZE = 64
NONCE_SIZE = 16
AUTH_TAG_SIZE = 16

# This allows to initialize the connection between firmware and bootloader
def do_handshake(ser, tag, nonce, debug=False):
    # Handshake for update
    ser.write(b'U')
    
    print('Waiting for bootloader to enter update mode...')
    while ser.read(1).decode() != 'U':
        pass

    # We send the tag and nonce for AES separately from the main frame blob
    ser.write(tag)
    ser.write(nonce)


def send_frame(ser, frame, debug=False):
    # assert that frame <= 64 bytes
    assert len(frame) <= 64
    
    # automatically pad frame to 64 bytes
    frame = frame + bytes(64 - len(frame))

    ser.write(frame)  # Write the frame...

    if debug:
        print(frame.hex())

    time.sleep(0.1)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        print(len(resp))
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))


def main(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, 'rb') as fp:
        firmware_blob = fp.read()


    # tag and nonce is first 16 + 16 bytes of firmware_blob
    tag = firmware_blob[:16]
    nonce = firmware_blob[16:32]
    firmware = firmware_blob[32:]
    
    # Initiate update handshake with the server
    do_handshake(ser, tag, nonce, debug=debug)
    
    print(len(firmware))

    # Iterate through the entire firmware blob
    for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
        data = firmware[frame_start: frame_start + FRAME_SIZE]

        if debug:
            print("Writing frame {} ({} bytes)...".format(idx, len(data)))

        # Send the frame
        send_frame(ser, data, debug=debug)

    # send final frame
    send_frame(ser, b'', debug=debug)

    print("Done writing firmware.")

    # Send a zero length payload to tell the bootlader to finish writing its page.
    ser.write(struct.pack('>H', 0x0000))

    return ser


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')

    parser.add_argument("--port", help="Serial port to send update over.",
                        required=True)
    parser.add_argument("--firmware", help="Path to firmware image to load.",
                        required=True)
    parser.add_argument("--debug", help="Enable debugging messages.",
                        action='store_true')
    args = parser.parse_args()

    print('Opening serial port...')
    ser = Serial(args.port, baudrate=115200, timeout=20)
    main(ser=ser, infile=args.firmware, debug=args.debug)
