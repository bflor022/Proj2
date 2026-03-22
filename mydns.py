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

def pick_next_server(authority, additional):
    ns_names = [rdata for name, rtype, rdata in authority if rtype == NS_REC]

    for name, rtype, rdata in additional:
        if rtype == A_REC and name in ns_names:
            return rdata

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
