import struct

from helpers import bin2str_ipaddress


class BGPOpen:
    UNPACK_STR = '!16sHBBHH4sB'

    def dissect(self, data):
        (marker,
         length,
         open_type,
         version,
         my_as,
         hold_time,
         bgp_id,
         optional_params_len) = struct.unpack_from(cls.UNPACK_STR, data)

        data = data[struct.calcsize(cls.UNPACK_STR) + optional_params_len:]

        # XXX: parse optional parameters
        #optional_params = []
        #while optional_params:
        #    op, bin_ops = dissect_optional_params(bin_ops)
        #    optional_params.extend(op)

        return data, {
            'version': version,
            'my_as': my_as,
            'hold_time': hold_time,
            'bgp_id': bin2str_ipaddress(bgp_id),
            'optional_params_len': optional_params_len,
        }
