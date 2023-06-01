#!/usr/bin/python3
from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES, NTLM
from getpass import getpass
import argparse

parser = argparse.ArgumentParser(description="Find the Fine Grained Password Policy users")
parser.add_argument("-u", "--username", help="Username", type=str, required=True)
parser.add_argument("-d", "--domain", help="Domain", type=str, required=True)
parser.add_argument("-o", "--output", help="Output File", type=str, required=False)
args = parser.parse_args()

domain = args.domain
output_file = args.output

target_dn = ""
domain_parts = domain.split(".")

for domain_part in domain_parts:
    target_dn += "DC=" + domain_part + ","

# Set LDAP server information
LDAP_SERVER = domain
LDAP_USERNAME = "{}\\{}".format(domain, args.username)
LDAP_PASSWORD = getpass("Password: ")
BASE_DN = target_dn[:-1]

# Set search parameters
SEARCH_FILTER = "(objectClass=user)"
SEARCH_ATTRIBUTES = ["sAMAccountName", "msDS-PSOApplied", "msDS-ResultantPSO"]

# Connect to LDAP server
server = Server(LDAP_SERVER)
conn = Connection(server, user=LDAP_USERNAME, password=LDAP_PASSWORD, authentication=NTLM)
conn.bind()

# Search for users and retrieve attributes
# source = https://stackoverflow.com/questions/48324418/ldap3-module-getting-more-than-1000-results-or-alternatives
entry_generator = conn.extend.standard.paged_search(
    search_base=BASE_DN, search_filter=SEARCH_FILTER, attributes=SEARCH_ATTRIBUTES, paged_size=10000, generator=True
)

for entry in entry_generator:
    if "attributes" in entry:
        attributes = entry["attributes"]
        username = attributes["sAMAccountName"]
        pso_applied = attributes["msDS-PSOApplied"]
        resultant_pso = attributes["msDS-ResultantPSO"]
        if len(pso_applied) or len(resultant_pso):
            print(f"User: {username}")
            print(f"  msDS-PSOApplied: {pso_applied}")
            print(f"  msDS-ResultantPSO: {resultant_pso}")
            if output_file:
                with open(output_file, "a") as file:
                    file.write(username + "\n")
