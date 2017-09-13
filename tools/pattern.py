#! /usr/bin/python3

import string
import argparse
import binascii

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_create = subparsers.add_parser('create', help="Generate a pattern of the provided length")
    parser_create.set_defaults(which='create')
    parser_create.add_argument('length', type=int, help="Length of non-repeating pattern string to generate")

    parser_offset = subparsers.add_parser('offset', help="Calculate offset to EIP given hex value")
    parser_offset.set_defaults(which='offset')
    parser_offset.add_argument('eip_pattern', type=str, help="Pattern observed in EIP at segfault")
    parser_offset.add_argument('length', type=int, help="Length provided to create command")

    args = parser.parse_args()
    args = vars(parser.parse_args())

    if not any(args.values()):
        parser.print_help()
    if args.get('which') == 'create':
        print(pattern_create(args['length']))
    if args.get('which') == 'offset':
        print('Offset:', pattern_offset(args['eip_pattern'], args['length']))

def pattern_create(length):
    pattern = ''
    set1 = [x for x in string.ascii_uppercase]
    set2 = [x for x in string.ascii_lowercase]
    set3 = [str(x) for x in range(0,10)]
    while True:
        for i in set1:
            for j in set2:
                for k in set3:
                    if len(pattern) == length:
                        return pattern
                    pattern += i
                    if len(pattern) == length:
                        return pattern
                    pattern += j
                    if len(pattern) == length:
                        return pattern
                    pattern += k
    return pattern

def pattern_offset(eip_pattern, length):
    try:
        pattern = pattern_create(length)
        offset = pattern.find(bytes.fromhex(eip_pattern.strip('0x')).decode('ascii')[::-1])
        if offset < 0:
            return "Not Found"
        else:
            return offset
    except:
        return "Invalid pattern provided"

if __name__ == '__main__':
    main()
