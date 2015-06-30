import sys
import struct
import binascii

LINE_LENGTH = 2066 # see windows sniffer sw help

psd = struct.Struct('< B I Q H')

print('{0}\t{1:>10s}\t{2}'.format('number', 'timestamp', 'packet'))

with open(sys.argv[1], 'rb') as fp:
    while True:
        data = fp.read(LINE_LENGTH)
        if len(data) == LINE_LENGTH:
            (_, packet_number, raw_timestamp, packet_length) = psd.unpack(data[0:15])
            packet = data[15:(15 + packet_length)]

            hpacket = binascii.hexlify(packet)
            fpacket = ' '.join(hpacket[i:i + 2].decode('utf-8') for i in range(0, len(hpacket), 2))

            print('{0:>6d}\t{1:>10d}\t{2}'.format(packet_number, raw_timestamp, fpacket))

        else:
            if len(data):
                print('Short read: {}'.format(len(data)))
            break
