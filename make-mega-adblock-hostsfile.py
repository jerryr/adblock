#!/usr/bin/env python3

import requests
import re
import argparse

parser = argparse.ArgumentParser(description='Generate hostsfile redirecting well known ad serving sites to a given IP')
parser.add_argument('-4', metavar='10.0.0.1', required=True,
                   help='IPv4 address to redirect to')
parser.add_argument('-6', metavar="fc02::1", required=False,
                   help='IPv6 address to redirect to')
parser.add_argument('-f', "--file", metavar='FILE', required=True,
                   help='Hosts file to write as output (will be truncated)')
args = vars(parser.parse_args())
ipv4_address = args["4"]
ipv6_address = args["6"]
outfile = args["file"]

invalid_hostnames = {'localhost'}
whitelist = {}

def remove_invalid(line):
    for h in invalid_hostnames:
        if line == h:
            return False
    if re.search("\.", line) == None:
        return False
    return True
    
def apply_whitelist(hostname):
    for w in whitelist:
        if re.search(w, hostname):
            return False
    return True

lists = {
    "yoyo": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "winhelp2002": "http://winhelp2002.mvps.org/hosts.txt",
    "adaway": "https://adaway.org/hosts.txt",
    "hosts-file": "http://hosts-file.net/.%5Cad_servers.txt",
    "malware-domain": "http://www.malwaredomainlist.com/hostslist/hosts.txt",
    "gjtech": "http://adblock.gjtech.net/?format=unix-hosts",
    "someone who cares": "http://someonewhocares.org/hosts/hosts",
    "mahakala": "http://adblock.mahakala.is/"
}

content = []
for listname, url in lists.items():
    print ("getting list " + listname)
    response = requests.get(url)
    if response.status_code != 200:
        print("Failed to get list from server")
        continue
    lines = []
    for line in response.iter_lines():
        line = line.strip()
        if line.startswith(b"#") == False:
            lines.append(str(line, 'utf-8'))

    #print("%d remaining after filtering out comments" %(len(lines)))
    for line in lines:
        words = line.split()
        if(len(words) >= 2):
            content.append(words[1])

content = list(filter(remove_invalid, content))
c1 = len(content)
print("Got %d hostnames" %(c1))
content.sort()
content = list(dict.fromkeys(content))
c2 = len(content)
print("Removed %d duplicates" %(c1-c2))
with open("whitelist.txt") as f:
    whitelist = f.read().splitlines()
content = list(filter(apply_whitelist, content))
c3 = len(content)
print("Removed %d items whitelisted" %(c2-c3))

with open(outfile, "w") as o:
    for hostname in content:
        try:
            o.write("%s %s\n" %(ipv4_address, hostname))
            if ipv6_address:
                o.write("%s %s\n" %(ipv6_address, hostname))
        except UnicodeEncodeError:
            print("skipped one record due to improper encoding")
print("Blacklisted %d domains total" %(c3))