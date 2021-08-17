import struct
import argparse
from io import BytesIO

from mz_header import MzHeader, from_bytes

class BitStream:
    def __init__(self, input_stream):
        self.input_stream = input_stream
        self.refresh_buffer()
    
    def get(self):
        bit = self.buffer & 1
        self.buffer = self.buffer >> 1
        self.buffer_length -= 1

        if self.buffer_length == 0:
            self.refresh_buffer()
        
        return bit
    
    def refresh_buffer(self):
        lowbyte, highbyte = self.input_stream.read(2)
        self.buffer = lowbyte + (highbyte << 8)
        self.buffer_length = 16

def segment_offset_to_absolute(segment, offset):
    return segment * 0x10 + offset

def convert_unsigned_to_signed(value, length):
    if value < (2**(length-1)):
        return value

    return value - 2**length

def copy_within_output_stream(output_stream, copy_distance, copy_amount):
    # we can copy repeating patterns with a copy_amount > copy_distance
    # e.g. look back -2 and copy 8 bytes
    while copy_amount > 0:
        end_index = copy_distance+copy_amount
        if end_index < 0:
            copy_bytes = bytes(output_stream.getvalue()[copy_distance:end_index])
        else:
            copy_bytes = bytes(output_stream.getvalue()[copy_distance:])
        copy_amount -= len(copy_bytes)
        output_stream.write(copy_bytes)

def unpack_code(packed_data):
    input_stream = BytesIO(packed_data)
    bitstream = BitStream(input_stream)
    output_stream = BytesIO()
    while True:
        bit = bitstream.get()
        if bit == 1:
            # copy byte across
            byte, = input_stream.read(1)
            output_stream.write(bytes([byte]))
        else:
            bit = bitstream.get()
            if bit == 1:
                lowbyte, highbyte = input_stream.read(2)
                copy_distance = 0xE000 | ((highbyte << 5) & 0xFF00) | lowbyte
                copy_distance = convert_unsigned_to_signed(copy_distance, 0x10)
                copy_amount = highbyte & 0x07
                if copy_amount:
                    copy_amount += 2
                    copy_within_output_stream(output_stream, copy_distance, copy_amount)
                else:
                    copy_amount, = input_stream.read(1)
                    if copy_amount == 0:
                        break
                    elif copy_amount == 1:
                        # segment reshuffle, ignore
                        pass
                    else:
                        copy_amount += 1
                        copy_within_output_stream(output_stream, copy_distance, copy_amount)
            else:
                high_bit = bitstream.get()
                low_bit = bitstream.get()
                copy_amount = (high_bit << 1) + low_bit + 2
                copy_distance, = input_stream.read(1)
                copy_distance = convert_unsigned_to_signed(0xFF00 + copy_distance, 0x10)
                copy_within_output_stream(output_stream, copy_distance, copy_amount)
    
    return output_stream.getvalue()

def unpack_relocations(packed_relocations):
    input_stream = BytesIO(packed_relocations)
    relocation = 0
    relocations = []
    while True:
        first_byte, = input_stream.read(1)
        if first_byte > 0:
            relocation += first_byte
            relocations.append(relocation)
        else:
            lowbyte, highbyte = input_stream.read(2)
            total = (highbyte << 0x08) + lowbyte
            if total == 0:
                relocation += 0xFFF
            elif total == 1:
                break
            else:
                relocation += total
                relocations.append(relocation)
    
    relocation_dwords = []
    for relocation in relocations:
        relocation_offset = relocation & 0x0F
        relocation_segment = relocation >> 4
        relocation_dword = (relocation_segment << 16) + relocation_offset
        packed_relocation_dword = struct.pack("<I", relocation_dword)
        relocation_dwords += packed_relocation_dword
    
    return bytes(relocation_dwords)

def build_header(old_header, unpacked_code, unpacked_relocations, initial_ip, initial_cs, initial_sp, initial_ss):
    num_pages = len(unpacked_code) // 0x200
    leftover_bytes = len(unpacked_code) % 0x200
    if leftover_bytes:
        num_pages += 1

    relocation_items = len(unpacked_relocations) // 4
    total_header_size = 0x1C + len(unpacked_relocations)
    header_paragraphs = total_header_size // 0x10
    leftover_header_bytes = total_header_size % 0x10
    if leftover_header_bytes:
        header_paragraphs += 1
    
    header = MzHeader(
        b"MZ",
        leftover_bytes,
        num_pages,
        relocation_items,
        header_paragraphs,
        old_header.minalloc,
        old_header.maxalloc,
        initial_ss,
        initial_sp,
        0,
        initial_ip,
        initial_cs,
        0x1C,
        0
    )
    return header

def unpacklzexe(filedata):
    header = from_bytes(filedata[:0x1C])
    loader_offset = segment_offset_to_absolute(header.initcs, 0)
    file_body = filedata[header.hdrsize * 0x10:]
    packed_data = file_body[:loader_offset]
    unpacked_code = unpack_code(packed_data)
    packed_relocations = file_body[loader_offset+0x158:]
    unpacked_relocations = unpack_relocations(packed_relocations)

    new_ip, new_cs, new_sp, new_ss = struct.unpack("<HHHH", file_body[loader_offset:loader_offset+8])
    
    header = build_header(header, unpacked_code, unpacked_relocations, new_ip, new_cs, new_sp, new_ss)
    
    return header.pack() + unpacked_relocations + unpacked_code

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('infile')
    parser.add_argument('outfile')
    args = parser.parse_args()
    infile = args.infile
    outfile = args.outfile

    with open(infile, "rb") as file:
        filedata = file.read()
    
    unpacked = unpacklzexe(filedata)

    with open(outfile, "wb") as file:
        file.write(unpacked)
