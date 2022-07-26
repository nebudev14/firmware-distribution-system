#!/usr/bin/env python
"""
Firmware Updater Tool

A frame consists of two sections:
1. Two bytes for the length of the data section
2. A data section of length defined in the length section

[ 0x02 ]  [ variable ]
--------------------
| Length | Data... |
--------------------

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
FRAME_SIZE = 16
SIGNATURE_SIZE = 64
NONCE_SIZE = 16
AUTH_TAG_SIZE = 16
VERIFY_SIZE = SIGNATURE_SIZE + NONCE_SIZE + AUTH_TAG_SIZE # Size of data we're using to ensure authenticity


def send_metadata(ser, metadata, debug=False):
    version, size = struct.unpack_from('<HH', metadata)
    print(f'Version: {version}\nSize: {size} bytes\n')

    # Handshake for update
    ser.write(b'U')
    
    print('Waiting for bootloader to enter update mode...')
    while ser.read(1).decode() != 'U':
        pass

    # Send size and version to bootloader.
    if debug:
        print(metadata)

    ser.write(metadata)

    # Wait for an OK from the bootloader.
    resp = ser.read()
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))


def send_frame(ser, frame, debug=False):
    ser.write(frame)  # Write the frame...

    if debug:
        print(frame)

    resp = ser.read()  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))


def main(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, 'rb') as fp:
        firmware_blob = fp.read()

    metadata = firmware_blob[:4]
    firmware = firmware_blob[4:len(firmware_blob)-()] # Exclude ECC signature, nonce, and auth tag
    firmware_verify = firmware_blob[-VERIFY_SIZE:]
    
    # Send version number/firmware size. 
    send_metadata(ser, metadata, debug=debug)
        
    # Send the first 60 bytes of firmware to achieve frame size of 64 bytes
    send_frame(ser, struct.pack("60s", firmware[:60]), debug=debug)
    
    for idx, frame_start in enumerate(range(60, len(firmware), FRAME_SIZE)):
        data = firmware[frame_start: frame_start + FRAME_SIZE]

        # Get length of data.
        length = len(data)
        frame_fmt = '>H{}s'.format(length)

        # Construct frame.
        frame = struct.pack(frame_fmt, length, data)

        if debug:
            print("Writing frame {} ({} bytes)...".format(idx, len(frame)))

        send_frame(ser, frame, debug=debug)
    
    # Send signature
    signature = firmware_verify[:SIGNATURE_SIZE] # Get the first 64 bytes after all the data has been sent
    nonce = firmware_verify[-(NONCE_SIZE+AUTH_TAG_SIZE):][:NONCE_SIZE] # Get the next 16 for nonce
    auth_tag = nonce = firmware_verify[-AUTH_TAG_SIZE:] # Get the last 16 bytes
    
    
    
    print("Done writing firmware.")

    # Send a zero length payload to tell the bootlader to finish writing it's page.
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
    ser = Serial(args.port, baudrate=115200, timeout=2)
    main(ser=ser, infile=args.firmware, debug=args.debug)


