from typing import Callable, Dict, List, Optional, Tuple, TypedDict
import socket
import sys
from struct import *
import argparse
import math
from functools import partial
from itertools import chain


class Parser:
    def __init__(self):
        self.__parser = self.__build_arg_parser()
        self.verbose: bool = False

    @staticmethod
    def __build_arg_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description='start sniffing for traffic')

        parser.add_argument(
            '-v',
            '--verbose',
            help='verbose output, or just messages with content',
            action='store_true'
        )

        return parser

    def parse_args(self) -> None:
        args = self.__parser.parse_args()
        self.verbose = args.verbose


def noop(_: bytes, __: int):
    # no operation
    pass


class Fragments:
    def __init__(
            self,
            on_reconstruct: Callable[[bytes, int, str, str], None] = noop,
            can_reconstruct: Callable[[Dict[int, Optional[bytes]]], None] = noop
    ) -> None:
        '''
        defrags is a mapping:
          (IP identifier fields): (frag_data_mapping)

        frag_data_mapping is a mapping:
          (offset): (data)
        '''
        self.defrags: Dict[str, Dict[int, Optional[bytes]]] = dict()

        # callback for operation to perform on successful reconstruction
        self.on_reconstruct: Callable[[bytes, int, str, str], None] = on_reconstruct

    def insert(
            self,
            ip_id: str,
            frag_offset: int,
            more_flag: bool,
            data: bytes,
            protocol: int,
            src_ip: str,
            dst_ip: str
    ) -> None:
        # find or initialize the defrag dict for given ip_id
        this_frag_dict = self.__get_or_initialize_frag_dict(ip_id)

        # find first section that is gap AND FO >= section.idx
        ordered_fragments: List[(int, Optional[bytes])] = sorted(
            this_frag_dict.items(), key=lambda pair: pair[0])

        # get ordered-index and offset value of the target gap (greatest valued offset that is <= frag_offset)
        (target_gap_index, target_gap_offset) = self.__first_valid_gap_ordered_index_and_offset(
            ordered_fragments, frag_offset)

        if target_gap_offset is None or target_gap_index is None:
            print('this defrag is already complete')
            return

        # get next available offset for this set of fragments, else set to infinity
        next_offset = ordered_fragments[target_gap_index + 1][0] \
            if target_gap_index + 1 != len(ordered_fragments) \
            else math.inf

        if frag_offset == target_gap_offset:
            # If flush with LHS of gap, reassign that entry in the dict
            this_frag_dict[target_gap_offset] = data
        else:
            # FO > section.idx
            # insert (data, idx = FO) after section
            this_frag_dict[frag_offset] = data

        # if data doesn't fill flush to RHS, add a gap after
        if more_flag and frag_offset + len(data) < next_offset:
            this_frag_dict[frag_offset + len(data)] = None

        #   when no more gaps, join all fragments into a single "bytes"
        #       push the bytes to self.finished_defrags
        #       del self.defrags[ip_id]
        #       and print the full packet

        # TODO: this has to parameterize on ip vs tcp
        no_gaps = len(list(
            filter(
                lambda item: item is None,
                this_frag_dict.values()
            )
        )) == 0
        if no_gaps:
            full_package = b''.join(list(
                filter(
                    lambda item: item is not None,
                    this_frag_dict.values()
                )
            ))
            # TODO: bring this back if we ever want to query packages after the fact
            # self.finished_defrags.append(full_package)
            del self.defrags[ip_id]

            self.on_reconstruct(full_package, protocol, src_ip, dst_ip)

    def __get_or_initialize_frag_dict(self, ip_id: str) -> Dict[int, Optional[bytes]]:
        if ip_id in self.defrags:
            return self.defrags[str(ip_id)]

        else:
            self.defrags[str(ip_id)] = dict([(0, None)])
            return self.defrags[str(ip_id)]

    @staticmethod
    def __first_valid_gap_ordered_index_and_offset(
            ordered_fragments: List[Tuple[int, Optional[bytes]]],
            min_offset: int
    ) -> Tuple[Optional[int], Optional[int]]:
        (reverse_index, first_gap) = next(
            filter(
                lambda item: item[1][1] is None and min_offset >= item[1][0],
                enumerate(reversed(ordered_fragments))
            ),
            (None, None)
        )
        first_gap_index = len(ordered_fragments) - reverse_index - 1 \
            if reverse_index is not None \
            else None

        target_first_gap = first_gap[0] if first_gap is not None else None
        return first_gap_index, target_first_gap


class HttpHeadersAndContent(TypedDict):
    headers: List[bytes]
    content: bytes


class ApplicationReader:
    def __init__(self):
        pass

    @staticmethod
    def __find_index(data: bytes, match_target: bytes, start: int = 0) -> Optional[int]:
        decoded_match = match_target.decode(errors='replace')
        candidates = [
            i for i in range(start, len(data))
                if data[i: i + len(match_target)].decode(errors='replace') == decoded_match
        ]
        default_candidates = [None]

        [first, *_] = chain(candidates, default_candidates)
        return first

    @staticmethod
    def __http_start(data: bytes) -> Optional[int]:
        match_target = b'HTTP/'
        return ApplicationReader.__find_index(data, match_target)

    @staticmethod
    def __build_http_headers_and_content(data: bytes) -> Optional[HttpHeadersAndContent]:
        http_start = ApplicationReader.__http_start(data)
        if http_start is None:
            return None
        else:
            next_start = http_start
            headers_and_content: HttpHeadersAndContent = HttpHeadersAndContent()
            clrf_length = len(b'\r\n')
            while next_start < len(data):
                next_clrf = ApplicationReader.__find_clrf_after(data, next_start)
                if next_clrf is not None and next_clrf != next_start:

                    # if found and is not a line containing only a CLRF
                    headers_and_content['headers'].append(data[next_start: next_clrf + clrf_length])
                    next_start = next_clrf + clrf_length

                else:
                    break

            if next_start < len(data):
                headers_and_content['content'] = data[next_start:]

            return headers_and_content

    @staticmethod
    def __find_clrf_after(data: bytes, start: int) -> Optional[int]:
        clrf = b'\r\n'
        return ApplicationReader.__find_index(data, clrf, start)

    @staticmethod
    def parse_application_layer(data: bytes) -> None:
        http_headers_and_content = ApplicationReader.__build_http_headers_and_content(data)
        if http_headers_and_content is not None:
            print('RECOGNIZED APPLICATION-LAYER PROTOCOL AS HTTP')
            print('-' * 80)
            print('HEADERS')
            print('-' * 80)
            print(''.join([h.decode(errors='replace') for h in http_headers_and_content['headers']]))
            print('-' * 80)
            content = http_headers_and_content['content']
            if len(content) > 0:
                print('DATA')
                print('-' * 80)
                print(content.decode(errors='replace'))
                print('-' * 80)
        else:
            print('UNRECOGNIZED APPLICATION-LAYER PROTOCOL')
            print('RAW DATA:')
            print('=' * 80)
            print(data)
            print('=' * 80)
            print('DECODED DATA:')
            print('=' * 80)
            print(data.decode(errors='replace'))
            print('=' * 80)


class TcpSegments:
    def __init__(self) -> None:
        self.segments = Fragments()
        self.initial_offsets: Dict[str, int] = dict()
        self.protocol: int = 6

    def insert(
            self,
            src_ip: str,
            dst_ip: str,
            src_port: int,
            dst_port: int,
            sequence: int,
            data: bytes
    ) -> None:
        src = f'{src_ip}:{src_port}'
        dst = f'{dst_ip}:{dst_port}'
        map_id = f'{src} -> {dst}'

        self.segments.insert(map_id, sequence, True, data, self.protocol, src_ip, dst_ip)
        ordered_fragments = list(
            map(
                lambda x: x[1],
                sorted(
                    self.segments.defrags[map_id].items(),
                    key=lambda pair: pair[0]
                )
            )
        )[1:-1]

        no_gaps = len(
            list(
                filter(
                    lambda item: item is None,
                    ordered_fragments
                )
            )
        ) == 0

        if no_gaps:
            print('\n\n')
            print('REORDERED TCP SEQUENCE', map_id)
            byte_stream = b''.join(ordered_fragments)
            ApplicationReader.parse_application_layer(byte_stream)

    def print_all(self) -> None:
        for (segment_id, data) in self.segments.defrags.items():
            print(f'{segment_id}:', data)


class TcpReader:
    def __init__(self) -> None:
        self.tcp_segments = TcpSegments()

    def parse_segment(self, packet: bytes, src_ip: str, dst_ip: str) -> None:
        '''
        (0) H source port #
        (1) H destination port #
        (2) L sequence # (counting BYTES -- not sequences)
        (3) L ack # (counting BYTES -- not sequences)
        (4) B 4-bit header-length (in # 32-bit words) + 4-bits of nothing
        (5) B 8 1-bit flags
        (6) H receive window
        (7) H checksum
        (8) H urgent-data pointer
                (options)
                (data)
        '''
        if len(packet) >= 20:

            (
                src_port,
                dst_port,
                sequence,
                acknowledgement,
                header_length_and_reserved,
                flags,
                receive_window,
                checksum,
                urgent_data_pointer
            ) = unpack('!HHLLBBHHH', packet[:20])

            tcp_header_row_length = header_length_and_reserved >> 4
            (
                cwr,
                ece,
                urg,
                ack,
                psh,
                rst,
                syn,
                fin
            ) = split_number_as_flags(flags, 8)

            tcp_header_byte_length = tcp_header_row_length * 4
            data_size = len(packet) - tcp_header_byte_length

            # get data from the packet
            data = packet[tcp_header_byte_length:]

            self.tcp_segments.insert(src_ip, dst_ip, src_port, dst_port, sequence, data)

            if verbose:
                print('\tSYN: ' + ('1' if syn else '0')
                      + '\n\tFIN: ' + ('1' if fin else '0')
                      + '\n\tACK: ' + ('1' if ack else '0')
                      + '\n\tSource Port : ' + str(src_port)
                      + '\n\tDest Port : ' + str(dst_port)
                      + '\n\tSequence Number : ' + str(sequence)
                      + '\n\tAcknowledgement : ' + str(acknowledgement)
                      + '\n\tTCP header length : ' + str(tcp_header_row_length)
                      )
                print('\t\tData : ', data)


arg_parser = Parser()
arg_parser.parse_args()
verbose = arg_parser.verbose


# Convert a string of 6 characters of ethernet address into a colon-separated hex string
def ethernet_address(a):
    print('ethernet_address: ', a)
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
        a[0],
        a[1],
        a[2],
        a[3],
        a[4],
        a[5]
    )
    return b


def split_on_n_least_significant_bytes(num, lsb_count) -> Tuple[int, int]:
    mask = int(
        ''.join(['1' for _ in range(lsb_count)]),
        2
    )
    most_significant_bytes = num >> lsb_count
    least_significant_bytes = num & mask
    return most_significant_bytes, least_significant_bytes


def extract_ip_version_and_header_length(version_and_ip_header_row_length) -> Tuple[int, int, int]:
    version = version_and_ip_header_row_length >> 4

    # ip_header_row_length = # header ROWS (groups of 4 bytes)
    ip_header_row_length = version_and_ip_header_row_length & 0xF

    # ip_header_length is the byte-length of the IP header
    ip_header_length = ip_header_row_length * 4

    return version, ip_header_row_length, ip_header_length


def split_number_as_flags(num, num_bits) -> List[bool]:
    format_string = '{0:0' + str(num_bits) + 'b}'
    return [i == '1' for i in format_string.format(num)]


def on_ip_reconstruct(tcp_reader: TcpReader, full_package: bytes, protocol: int, src_ip: str, dst_ip: str) -> None:
    if verbose:
        print('finished IP reconstruction:')
        print(full_package)

    # TCP protocol
    if protocol == 6:
        if verbose:
            print('\n\nTCP\n\n')
        # now unpack them :)
        tcp_reader.parse_segment(full_package, src_ip, dst_ip)

    # ICMP Packets
    elif protocol == 1:
        icmph_length = 4
        icmp_header = base_packet[:icmph_length]

        # now unpack them :)
        icmph = unpack('!BBH', icmp_header)

        icmp_type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]

        if verbose:
            print(
                '\n\nICMP\n\n'
                + '\n\tType : ' + str(icmp_type)
                + '\n\tCode : ' + str(code)
                + '\n\tChecksum : ' + str(checksum)
            )

        data_size = len(base_packet) - icmph_length

        # get data from the packet
        data = base_packet[icmph_length:]

        if verbose:
            print('\t\tData : ' + str(data))

    # UDP packets
    elif protocol == 17:
        udph_length = 8
        udp_header = base_packet[:udph_length]

        # now unpack them :)
        '''
        (0) H source port #
        (1) H destination port #
        (2) H length in bytes (of UDP segment, including UDP header)
        (3) H checksum
        '''
        udph = unpack('!HHHH', udp_header)

        src_port = udph[0]
        dst_port = udph[1]
        length = udph[2]
        checksum = udph[3]

        if verbose:
            print('\n\nUDP\n\nSource Port : ' + str(src_port) + '\nDest Port : ' +
                  str(dst_port) + '\nLength : ' + str(length) + '\nChecksum : ' + str(checksum))

        # h_size = eth_length + ip_header_length + udph_length
        # data_size = len(packet) - udph_length

        # get data from the packet
        data = base_packet[udph_length:]

        if verbose:
            print('Data : ', data)

    # some other Transport Protocol like IGMP
    else:
        if verbose:
            print('Protocol other than TCP/UDP/ICMP')


class IpReader:
    def __init__(self):
        # TODO: be printing something...
        self.tcp_reader = TcpReader()
        frags_callback: Callable[[bytes, int, str, str], None] = partial(on_ip_reconstruct, self.tcp_reader)
        self.ip_fragments = Fragments(frags_callback)

    def process_packet(self, packet: bytes):
        # Parse IP header
        # take first 20 characters for the ip header minus options
        ip_header = packet[:20]

        # now unpack them :)
        '''
        (0) B = 4-bit version + 4-bit header length
        (1) B = type of service
        (2) H = Total Length
        (3) H = Identification
        (4) H = 3-bit flags + 13-bit fragment offset
        (5) B = TTL
        (6) B = Protocol
        (7) H = Header Checksum
        (8) 4s = source IP
        (9) 4s = destimation IP
            (options if any + padding if needed)
            (payload)
        '''
        (
            version_and_ip_row_length,
            tos,
            total_length,
            identification,
            flags_and_offset,
            ttl,
            protocol,
            checksum,
            src_ip_raw,
            dst_ip_raw
        ) = unpack('!BBHHHBBH4s4s', ip_header)

        (version, ip_header_row_length, ip_header_length) = extract_ip_version_and_header_length(
            version_and_ip_row_length)

        (flags, fragment_offset) = split_on_n_least_significant_bytes(flags_and_offset, 13)

        (
            reserved_flat,
            dont_fragment_flag,
            more_flag
        ) = split_number_as_flags(flags, 3)

        src_ip = socket.inet_ntoa(src_ip_raw)
        dst_ip = socket.inet_ntoa(dst_ip_raw)

        if verbose:
            print('\tVersion : ' + str(version)
                  + '\n\tIP Header Length : ' + str(ip_header_row_length)
                  + '\n\tTTL : ' + str(ttl)
                  + '\n\tProtocol : ' + str(protocol)
                  + '\n\tSource Address : ' + str(src_ip)
                  + '\n\tDestination Address : ' + str(dst_ip)
                  )

        # add to defrag object
        self.ip_fragments.insert(
            str(identification),
            fragment_offset,
            more_flag,
            packet[ip_header_length:],
            protocol,
            src_ip,
            dst_ip
        )


ip_reader = IpReader()

# create an AF_PACKET type raw socket (that's basically packet level)
# define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error:
    print('Socket could not be created')
    sys.exit()

# receive packets
while True:
    (base_packet, _) = s.recvfrom(65565)

    # parse ethernet header
    eth_length = 14

    eth_header = base_packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])

    if verbose:
        print(
            'Destination MAC : ' + ethernet_address(base_packet[0:6])
            + ' Source MAC : ' + ethernet_address(base_packet[6:12])
            + ' Protocol : ' + str(eth_protocol)
        )

    # shed the ethernet header
    base_packet = base_packet[eth_length:]

    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
        ip_reader.process_packet(base_packet)
    else:
        if verbose:
            print('Unrecognized link layer protocol')
    print()
