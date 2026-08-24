#!/usr/bin/env python3

import sys
from elftools.elf.elffile import ELFFile
import argparse

FLASH_BASE = 0x60000000

parser = argparse.ArgumentParser("flash_image_maker")
parser.add_argument("-o", "--output-file", type=str, help="Output filename", required=True)
parser.add_argument("-s", "--output-size", type=int, help="Size of output flash file", required=False, default=4*1024*1024)
parser.add_argument("input_files", nargs="+")
args = parser.parse_args()

flash_buffer = bytearray(args.output_size)

for ifile in args.input_files:
    with open(ifile, "rb") as f:
        elffile = ELFFile(f)

        if elffile['e_type'] == 'ET_EXEC':
            for segment in elffile.iter_segments():
                if segment['p_type'] == 'PT_LOAD' and segment['p_filesz'] > 0:
                    data = segment.data()
                    paddr = segment['p_paddr']
                    flash_offset = paddr - FLASH_BASE

                    if flash_offset < 0 or (flash_offset + len(data)) > args.output_size:
                        print(f"Segment outside flash: {hex(paddr)} - {hex(paddr + len(data))}")
                        sys.exit(1)
                    
                    flash_buffer[flash_offset:flash_offset + len(data)] = data

                    print(f"{str(ifile)}: PT_LOAD: {hex(paddr)} - {hex(paddr + len(data))}")
                    
        if elffile['e_type'] == 'ET_REL':
            for section in elffile.iter_sections():
                if section['sh_type'] == 'SHT_PROGBITS' and section['sh_size'] > 0:
                    data = section.data()
                    paddr = section['sh_addr']

                    flash_offset = paddr - FLASH_BASE

                    if flash_offset < 0 or (flash_offset + len(data)) > args.output_size:
                        print(f"Section outside flash: {hex(paddr)} - {hex(paddr + len(data))}")
                        sys.exit(1)
                    
                    flash_buffer[flash_offset:flash_offset + len(data)] = data

                    print(f"{str(ifile)}: SHT_PROGBITS: {hex(paddr)} - {hex(paddr + len(data))}")

with open(args.output_file, "wb") as f:
    f.write(flash_buffer)

# e.g. python3 .\flash_image_maker.py -o test.img ..\ssbl-a\build\gkv4_ssbl_a.elf ..\gkos\build\gkos.bin.elf ..\secure_monitor\build\gkos_sm.bin.elf ..\cm33-firmware\build\gkv4_cm33.elf
# run with: /build/qemu-system-aarch64 -machine gk -kernel ~/jncro/source/repos/gk/Firmware-v4/fsbl-a/build/gkv4_fsbl_a.elf -m 1G -pflash ~/jncro/source/repos/gk/Firmware-v4/flash_image_maker/test.img  -sd ~/sd.qcow2 -monitor stdio