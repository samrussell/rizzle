import argparse
import struct

class MzHeader:
    def __init__(self,
            signature,
            partpage,
            pagecnt,
            relocnt,
            hdrsize,
            minalloc,
            maxalloc,
            initss,
            initsp,
            chksum,
            initip,
            initcs,
            tabloff,
            overlayno):
        self.signature = signature
        self.partpage = partpage
        self.pagecnt = pagecnt
        self.relocnt = relocnt
        self.hdrsize = hdrsize
        self.minalloc = minalloc
        self.maxalloc = maxalloc
        self.initss = initss
        self.initsp = initsp
        self.chksum = chksum
        self.initip = initip
        self.initcs = initcs
        self.tabloff = tabloff
        self.overlayno = overlayno
    
    def pack(self):
        return struct.pack('<2sHHHHHHHHHHHHH', *vars(self).values())
    
    def __repr__(self):
        return "MzHeader(%s)" % (", ".join("%s=%s" % pair for pair in vars(self).items()))

def from_bytes(raw):
    fields = struct.unpack('<2sHHHHHHHHHHHHH', raw)
    
    return MzHeader(*fields)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('infile')
    args = parser.parse_args()
    infile = args.infile

    with open(infile, "rb") as file:
        header = from_bytes(file.read(0x20))
    
    print(header)
