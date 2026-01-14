#!/usr/bin/env python3
import struct
import sys
import os

# Header V4 Structure (Vendor Boot)
# magic: 8s
# version: I
# page_size: I
# kernel_addr: I
# ramdisk_addr: I
# ramdisk_size: I
# cmdline: 2048s
# tags_addr: I
# dtb_size: I
# dtb_addr: Q
# vendor_ramdisk_table_size: I
# vendor_ramdisk_table_entry_num: I
# vendor_ramdisk_table_entry_size: I
# bootconfig_size: I

def parse_header(file_path):
    with open(file_path, 'rb') as f:
        f.seek(0)
        # Read 1 page
        page_0 = f.read(4096) 
        
        # Manually unpack
        magic = page_0[0:8]
        if magic != b'VNDRBOOT':
            print(f"Error: Invalid Magic: {magic}")
            return None
        
        # version at 8
        version = struct.unpack('<I', page_0[8:12])[0]
        # page_size at 12
        page_size = struct.unpack('<I', page_0[12:16])[0]
        # ramdisk_size at 24
        ramdisk_size = struct.unpack('<I', page_0[24:28])[0]
        
        # cmdline starts at 28, length 2048
        # dtb_size at 28 + 2048 = 2076? No.
        # struct vendor_boot_img_hdr_v3 {
        #     uint8_t magic[8];
        #     uint32_t header_version;
        #     uint32_t page_size;
        #     uint32_t kernel_addr;
        #     uint32_t ramdisk_addr;
        #     uint32_t ramdisk_size;
        #     uint8_t cmdline[2048];
        #     uint32_t tags_addr;
        #     uint32_t dtb_size;
        #     uint64_t dtb_addr;
        #     ...
        # }
        # Offsets:
        # magic: 0-8
        # version: 8-12
        # page_size: 12-16
        # kernel_addr: 16-20
        # ramdisk_addr: 20-24
        # ramdisk_size: 24-28
        # cmdline: 28-2076 (2048 bytes)
        # tags_addr: 2076-2080
        # dtb_size: 2080-2084
        # dtb_addr: 2084-2092 (8 bytes)
        # vendor_ramdisk_table_size: 2092-2096
        # vendor_ramdisk_table_entry_num: 2096-2100
        # vendor_ramdisk_table_entry_size: 2100-2104
        # bootconfig_size: 2104-2108

        dtb_size = struct.unpack('<I', page_0[2080:2084])[0]
        vendor_ramdisk_table_size = struct.unpack('<I', page_0[2092:2096])[0]
        bootconfig_size = struct.unpack('<I', page_0[2104:2108])[0]

        return {
            'version': version,
            'page_size': page_size,
            'ramdisk_size': ramdisk_size,
            'dtb_size': dtb_size,
            'vendor_ramdisk_table_size': vendor_ramdisk_table_size,
            'bootconfig_size': bootconfig_size,
        }

def align(n, page_size):
    return ((n + page_size - 1) // page_size) * page_size

def extract(file_path):
    info = parse_header(file_path)
    if not info: return

    page_size = info['page_size']
    
    # Calculate Header Size
    # Struct size is approx 2108 bytes for V4
    # magic(8)+vers(4)+page(4)+kern(4)+ram(4)+ramsz(4) = 28
    # cmdline(2048) = 2076
    # tags(4)+dtbsz(4)+dtbaddr(8) = 2092 (V3 end)
    # vrt_sz(4)+vrt_num(4)+vrt_entry(4)+bootconf_sz(4) = 2108 (V4 end)
    header_real_size = 2108
    header_aligned_size = align(header_real_size, page_size)
    
    offset = header_aligned_size # Start after header pages

    
    with open(file_path, 'rb') as f:
        # Extract Ramdisk (Potential Kernel)
        f.seek(offset)
        ramdisk_data = f.read(info['ramdisk_size'])
        with open('ramdisk.extracted', 'wb') as out:
            out.write(ramdisk_data)
        print(f"Extracted ramdisk.extracted ({len(ramdisk_data)} bytes)")
        
        offset += align(info['ramdisk_size'], page_size)
        
        # Extract DTB
        f.seek(offset)
        dtb_data = f.read(info['dtb_size'])
        with open('dtb.extracted', 'wb') as out:
            out.write(dtb_data)
        print(f"Extracted dtb.extracted ({len(dtb_data)} bytes)")
        
        offset += align(info['dtb_size'], page_size)
        
        # Extract Vendor Ramdisk Table
        if info['vendor_ramdisk_table_size'] > 0:
            f.seek(offset)
            vrt_data = f.read(info['vendor_ramdisk_table_size'])
            with open('vrt.extracted', 'wb') as out:
                out.write(vrt_data)
            print(f"Extracted vrt.extracted ({len(vrt_data)} bytes)")
            offset += align(info['vendor_ramdisk_table_size'], page_size)

        # Extract Bootconfig
        if info['bootconfig_size'] > 0:
            f.seek(offset)
            bc_data = f.read(info['bootconfig_size'])
            with open('bootconfig.extracted', 'wb') as out:
                out.write(bc_data)
            print(f"Extracted bootconfig.extracted ({len(bc_data)} bytes)")

def repack(original_img, new_kernel, output_img):
    info = parse_header(original_img)
    if not info: return
    
    # Calculate Header Size
    header_real_size = 2108
    header_aligned_size = align(header_real_size, info['page_size'])
    
    # Read original header (all pages)
    with open(original_img, 'rb') as f:
        header = bytearray(f.read(header_aligned_size))

    # Read new kernel
    with open(new_kernel, 'rb') as f:
        kernel_data = f.read()
    
    page_size = info['page_size']
    offset_ramdisk = header_aligned_size
    offset_dtb = offset_ramdisk + align(info['ramdisk_size'], page_size)
    offset_vrt = offset_dtb + align(info['dtb_size'], page_size)
    offset_bc = offset_vrt + align(info['vendor_ramdisk_table_size'], page_size)
    
    # Read other components from original image
    with open(original_img, 'rb') as f:
        f.seek(offset_dtb)
        dtb_data = f.read(info['dtb_size'])
        
        vrt_data = b''
        if info['vendor_ramdisk_table_size'] > 0:
            f.seek(offset_vrt)
            vrt_data = f.read(info['vendor_ramdisk_table_size'])
            
        bc_data = b''
        if info['bootconfig_size'] > 0:
            f.seek(offset_bc)
            bc_data = f.read(info['bootconfig_size'])

    # Update Header with new sizes
    new_ramdisk_size = len(kernel_data)
    struct.pack_into('<I', header, 24, new_ramdisk_size)
    
    # Reconstruct Image
    with open(output_img, 'wb') as out:
        out.write(header)
        out.write(kernel_data)
        out.write(b'\x00' * (align(len(kernel_data), page_size) - len(kernel_data)))
        
        out.write(dtb_data)
        out.write(b'\x00' * (align(len(dtb_data), page_size) - len(dtb_data)))
        
        if len(vrt_data) > 0:
            out.write(vrt_data)
            out.write(b'\x00' * (align(len(vrt_data), page_size) - len(vrt_data)))
            
        if len(bc_data) > 0:
            out.write(bc_data)
            out.write(b'\x00' * (align(len(bc_data), page_size) - len(bc_data)))
            
    print(f"Repacked {output_img} successfully.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: script <info|extract|repack> [args]")
        sys.exit(1)
    
    if sys.argv[1] == 'info':
        print(parse_header(sys.argv[2]))
    elif sys.argv[1] == 'extract':
        extract(sys.argv[2])
    elif sys.argv[1] == 'repack':
        repack(sys.argv[2], sys.argv[3], sys.argv[4])
