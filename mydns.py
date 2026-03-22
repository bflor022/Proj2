#!/usr/bin/env python3

# mydns.py
# CNT 4713 Project 2
#
# Group Members:
# 1. Don Bunt - 6547594
# 2. Bryan Flores - 56840874
# 3. Alvaro Lopez Abreu - 6393451
# 4. Josed Vasquez - 6263620
#
# run:
# python mydns.py domain-name root-dns-ip

import sys
import socket
import struct
import random

# dns uses port 53
DNS_PORT = 53

# normal dns udp reply size
BUF_SIZE = 512

# timeout so it does not hang forever
TIMEOUT = 5

# A record type
A_REC = 1

# NS record type
NS_REC = 2

# internet class
IN_CLASS = 1


# this turns cs.fiu.edu into dns label format
def make_name(domain):
    parts = domain.split(".")
    name = b""

    for p in parts:
        name += bytes([len(p)]) + p.encode()

    name += b"\x00"
    return name


# this builds the dns query packet
def make_query(domain):
    msg_id = random.randint(0, 65535)

    header = struct.pack(
        "!HHHHHH",
        msg_id,
        0,
        1,
        0,
        0,
        0
    )

    qname = make_name(domain)

    question = qname + struct.pack("!HH", A_REC, IN_CLASS)

    return msg_id, header + question


# send query to a DNS server (root or intermediate)
def send_query(server, domain):
    print("----------------------------------------------------------------")
    print("DNS server to query: " + server)

    _, packet = make_query(domain)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    sock.sendto(packet, (server, DNS_PORT))

    data, _ = sock.recvfrom(BUF_SIZE)

    sock.close()

    print("Reply received.")

    return data


# read a domain name from DNS response (handles compression)
def read_name(data, offset):
    name_parts = []
    visited = set()

    while True:
        if offset >= len(data):
            break

        length = data[offset]

        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer in visited:
                break
            visited.add(pointer)
            sub_name, _ = read_name(data, pointer)
            name_parts.append(sub_name)
            offset += 2
            return ".".join(filter(None, name_parts)), offset

        elif length == 0:
            offset += 1
            break

        else:
            offset += 1
            label = data[offset:offset + length].decode("ascii", errors="replace")
            name_parts.append(label)
            offset += length

    return ".".join(name_parts), offset


# parse a resource record from DNS response
def parse_rr(data, offset):
    name, offset = read_name(data, offset)

    if offset + 10 > len(data):
        return (name, 0, ""), len(data)

    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
    offset += 10

    rdata_start = offset
    rdata_end = offset + rdlength

    if rdata_end > len(data):
        return (name, rtype, ""), len(data)

    if rtype == A_REC and rdlength == 4:
        ip_bytes = data[rdata_start:rdata_end]
        rdata = ".".join(str(b) for b in ip_bytes)
    elif rtype == NS_REC:
        rdata, _ = read_name(data, rdata_start)
    else:
        rdata = data[rdata_start:rdata_end]

    offset = rdata_end
    return (name, rtype, rdata), offset


# parse full DNS reply into sections
def parse_reply(data):
    if len(data) < 12:
        return [], [], []

    msg_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])

    offset = 12

    for _ in range(qdcount):
        _, offset = read_name(data, offset)
        offset += 4

    answers = []
    authority = []
    additional = []

    for _ in range(ancount):
        rr, offset = parse_rr(data, offset)
        answers.append(rr)

    for _ in range(nscount):
        rr, offset = parse_rr(data, offset)
        authority.append(rr)

    for _ in range(arcount):
        rr, offset = parse_rr(data, offset)
        additional.append(rr)

    return answers, authority, additional


# display DNS reply contents
def display_reply(answers, authority, additional):
    print("----------------------------------------------------------------")
    print("Reply received. Content overview:")
    print(str(len(answers)) + " Answers.")
    print(str(len(authority)) + " Intermediate Name Servers.")
    print(str(len(additional)) + " Additional Information Records.")

    print("Answers section:")
    for name, rtype, rdata in answers:
        if rtype == A_REC:
            print("Name :", name, "IP:", rdata)

    print("Authority Section:")
    for name, rtype, rdata in authority:
        print("Name :", name, "Name Server:", rdata)

    print("Additional Information Section:")
    for name, rtype, rdata in additional:
        if rtype == A_REC:
            print("Name :", name, "IP :", rdata)


# choose next DNS server using Authority + Additional sections
def pick_next_server(authority, additional):
    ns_names = [rdata for name, rtype, rdata in authority if rtype == NS_REC]

    for name, rtype, rdata in additional:
        if rtype == A_REC and name in ns_names:
            return rdata

    return None


# main iterative DNS resolution loop
# repeatedly:
#   send query
#   receive and parse reply
#   display results
#   stop if A record found
#   otherwise pick next server and repeat
def main():
    if len(sys.argv) != 3:
        print("Usage: python mydns.py domain-name root-dns-ip")
        sys.exit(1)

    domain = sys.argv[1]
    server = sys.argv[2]

    while True:
        try:
            data = send_query(server, domain)
        except socket.timeout:
            print("Timeout waiting for reply from", server)
            sys.exit(1)
        except Exception as e:
            print("Error querying", server, ":", e)
            sys.exit(1)

        # receive reply and parse DNS sections
        answers, authority, additional = parse_reply(data)

        # display full reply contents
        display_reply(answers, authority, additional)

        # check if final IP (A record) found
        final_ips = [(name, rdata) for name, rtype, rdata in answers if rtype == A_REC]
        if final_ips:
            break

        # extract next DNS server from authority/additional sections
        next_server = pick_next_server(authority, additional)
        if next_server is None:
            print("Could not find a next DNS server to query. Stopping.")
            sys.exit(1)

        # send query to intermediate server in next iteration
        server = next_server

    print("----------------------------------------------------------------")


# run main
if __name__ == "__main__":
    main()
