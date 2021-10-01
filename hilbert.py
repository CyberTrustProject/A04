import time
import os
import os.path, math, string, sys
import scurve
from scurve import utils, draw
from PIL import Image, ImageDraw
from mobileNet import *

dst = ""
class _Color:
    def __init__(self, data, block):
        self.data, self.block = data, block
        s = list(set(data))
        s.sort()
        self.symbol_map = {v : i for (i, v) in enumerate(s)}

    def __len__(self):
        return len(self.data)

    def point(self, x):
        if self.block and (self.block[0]<=x<self.block[1]):
            return self.block[2]
        else:
            return self.getPoint(x)

class ColorClass(_Color):
    def getPoint(self, x):
        c = self.data[x]
        if c == 0:
            return [0, 0, 0]
        elif c == 255:
            return [255, 255, 255]
        elif chr(c) in string.printable:
            return [55, 126, 184]
        else:
            return [228, 26, 28]

def drawmap_unrolled(map, size, csource, name):
    map = scurve.fromSize(map, 2, size**2)
    c = Image.new("RGB", (size, size*4))
    cd = ImageDraw.Draw(c)
    step = len(csource)/float(len(map)*4)
    for quad in range(4):
        for i, p in enumerate(map):
            off = (i + (quad * size**2))
            color = csource.point(
                        int(off * step)
                    )
            x, y = tuple(p)
            cd.point(
                (x, y + (size * quad)),
                fill=tuple(color)
            )
    c.save(name)


#Add a count function to image name output (possible hash of image as name value)
def siteInput(input, output):
    block = None
    d = input
    dst = "/var/log/suricata/malwaresquid/images/tmp/" + output + ".jpg"
    csource = ColorClass(d, block)
    drawmap_unrolled("hilbert", 256, csource, dst)
    return imagePassing(dst)
