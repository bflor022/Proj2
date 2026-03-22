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


# this sends a query to one dns server
def send_query(server, domain):
    print("----------------------------------------------------------------")
    print("DNS server to query: " + server)

    _, packet = make_query(domain)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    sock.sendto(packet, (server, DNS_PORT))

    data, _ = sock.recvfrom(BUF_SIZE)

    sock.close()

    print("Reply received (raw).")

    return data


# ===========================
# TODO: RECEIVE reply from root DNS server (15%)
# ===========================
# we already get raw data from send_query()
# next step is to parse the reply into sections

#takes DNS header's first 12 bytes and converts to integers
header = struct.unpack("!HHHHHH", data[:12])

ancount = header[3] # number of answer records
nscount = header[4] # number authority records
arcount = header[5] # number of additional records


def parse_dns_reply(data):
    # get the first 12 bytes (DNS header) and turn them into numbers
    header = struct.unpack("!HHHHHH", data[:12])

    # how many answers came back
    ancount = header[3]

    # how many name servers we got (authority section)
    nscount = header[4]

    # how many extra records (IPs for those servers)
    arcount = header[5]

    # print basic info about the reply
    print("----------------------------------------------------------------")
    print("Reply received. Content overview:")
    print(str(ancount) + " Answers.")
    print(str(nscount) + " Intermediate Name Servers.")
    print(str(arcount) + " Additional Information Records.")

    # just printing section titles for now
    print("Answers section:")
    print("Authority Section:")
    print("Additional Information Section:")

    # start reading after the header
    offset = 12

    # skip the question part (domain name)
    while data[offset] != 0:
        offset += 1
    offset += 5

    ns_ips = {}

    # skip answers if there are any
    for _ in range(ancount):
        offset += 2
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10 + rdlength

    # go through authority section (name servers)
    for _ in range(nscount):
        offset += 2
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10 + rdlength

    # get IPs from additional section
    for _ in range(arcount):
        offset += 2
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10

        if rtype == A_REC:
            ip = ".".join(str(b) for b in data[offset:offset+4])
            ns_ips[len(ns_ips)] = ip

        offset += rdlength

    # pick one server to use next
    if ns_ips:
        next_server = list(ns_ips.values())[0]
        print("Next DNS server to query:", next_server)
        return next_server

    return None

# ===========================
# TODO: SEND query to intermediate servers (15%)
# ===========================
# take the IP from previous step and call send_query again


# ===========================
# TODO: RECEIVE reply from intermediate servers (15%)
# ===========================
# same process as root, just repeat until we get final answer


# ===========================
# TODO: DISPLAY IPs for queried domain name (15%)
# ===========================
# once we find A record:
# print:
# Name : domain IP: x.x.x.x


# ===========================
# TODO: MAIN LOOP FOR ITERATION
# ===========================
# loop:
#   send query
#   parse reply
#   print reply
#   check if answer found
#   if not:
#       get next server and repeat


# main part of program
def main():
    domain = sys.argv[1]
    server = sys.argv[2]

    print("Starting DNS lookup for:", domain)

    # right now only does one query (root)
    data = send_query(server, domain)

    print("\nRaw response size:", len(data))
    print("TODO: finish parsing and iteration")


# run main
if __name__ == "__main__":
    main()
