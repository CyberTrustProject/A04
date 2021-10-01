from scurve.hilbert import *
#from scurve.zigzag import *
#from scurve.zorder import *
#from scurve.natural import *
#from scurve.graycurve import *
#from scurve.hcurve import *


curveMap = {
#    "hcurve": hcurve.Hcurve,
    "hilbert": hilbert.Hilbert,
#    "zigzag": zigzag.ZigZag,
#    "zorder": zorder.ZOrder,
#    "natural": natural.Natural,
#    "gray": graycurve.GrayCurve,
}
curves = curveMap.keys()


def fromSize(curve, dimension, size):
    """
        A convenience function for creating a specified curve by specifying
        size and dimension. All curves implement this common interface.
    """
    return curveMap[curve].fromSize(dimension, size)


def fromOrder(curve, dimension, order):
    """
        A convenience function for creating a specified curve by specifying
        order and dimension. All curves implement this common interface, but
        the meaning of "order" may differ for each curve.
    """
    return curveMap[curve](dimension, order)
    
