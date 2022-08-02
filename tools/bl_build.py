#!/usr/bin/env python
"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import argparse
import os
import pathlib
import shutil
import subprocess

from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC

FILE_DIR = pathlib.Path(__file__).parent.absolute()


# converts binary string to c array so that we can take it in as input
def arrayize(binary_string):
    return '{' + ','.join([hex(char) for char in binary_string]) + '}'

def copy_initial_firmware(binary_path):
    """
    Copy the initial firmware binary to the bootloader build directory
    Return:
        None
    """
    # Change into directory containing tools
    os.chdir(FILE_DIR)
    bootloader = FILE_DIR / '..' / 'bootloader'
    shutil.copy(binary_path, bootloader / 'src' / 'firmware.bin')
def make_bootloader():
    """
    Build the bootloader from source.

    Return:
        True if successful, False otherwise.
    """
    # Change into directory containing bootloader.
    bootloader = FILE_DIR / '..' / 'bootloader'
    os.chdir(bootloader)

    aes_key = get_random_bytes(16)
    vkey = get_random_bytes(64)
    
    ecc_key = ECC.generate(curve='p256')

    private_key = ecc_key.export_key(format='DER')
    public_key = ecc_key.public_key().export_key(format='raw')

    # write keys to file
#     with open('secret_build_output.txt', 'wb+') as f:
#         f.write(aes_key)
#         f.write(private_key)
#         f.write(public_key)
#         f.write(vkey)
    aes_key = b"\xc4\xb4\x5e\x3\xf3\xa6\x54\xb0\x73\xfc\xd5\xed\x77\xb1\xda\xd7"
    v_key = b"\x5d\xd7\x3a\x13\x8f\xdb\xe7\x8e\x21\x67\xf6\x1a\xfa\x67\x56\xd\x9\xc0\x76\xd3\xb4\x28\x6d\x33\x11\xe4\xb1\x20\x34\xf6\xee\xbd\xf9\x8b\x46\xe2\x9f\x4b\x6c\xed\xd2\xeb\x7e\xff\x5b\xc7\xeb\x11\xfd\xcd\x98\xbc\x2e\x4c\xde\xc\xa1\xbb\x57\x23\x45\x4\x76\xe9"
    ecc_key = b"\x4\x57\xfa\xd7\x74\x48\x42\x71\xb4\xe2\xfe\xd3\x59\xd3\xe8\x85\x6a\x6d\xea\xe2\xdd\xbb\x1f\x51\xbe\xe0\x62\xc0\x50\x47\x35\xa5\x8b\xc7\x77\xe7\xdf\x39\x99\x40\x8c\xd1\x5d\xda\xe2\xcd\x70\x21\x59\xb3\x55\x9e\xfb\xb0\xae\x50\x8f\xac\x7e\x91\x56\xca\x86\x47\xca"
    with open('secret.h',wb) as f:
        f.write(aes_key)
        f.write(v_key)
        f.write(aecc_key)
    subprocess.call('make clean', shell=True)
    status = subprocess.call(f'make AES_KEY={arrayize(aes_key)} V_KEY={arrayize(v_key)} ECC_KEY={arrayize(ecc_key)}', shell=True)

    # Return True if make returned 0, otherwise return False.
    return (status == 0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Bootloader Build Tool')
    parser.add_argument("--initial-firmware", help="Path to the the firmware binary.", default=None)
    args = parser.parse_args()
    if args.initial_firmware is None:
        binary_path = FILE_DIR / '..' / 'firmware' / 'firmware' / 'gcc' / 'main.bin'
    else:
        binary_path = os.path.abspath(pathlib.Path(args.initial_firmware))

    if not os.path.isfile(binary_path):
        raise FileNotFoundError(
            "ERROR: {} does not exist or is not a file. You may have to call \"make\" in the firmware directory.".format(
                binary_path))

    copy_initial_firmware(binary_path)
    make_bootloader()
