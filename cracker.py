#!/usr/bin/env python3
import os
import sys
import subprocess
from shutil import which

from identifier import HashID

if which("hashcat"):
    print("hashcat found, cracking..")

else:
    print("hashcat not installed, installing manually")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "hashcat"])

hash = sys.argv[1]

with open("hash.txt","w+") as handle:
    handle.write(hash)

hashid = HashID()
modes = hashid.identifyHash(hash)

if modes is not None:
    for index,mode in enumerate(modes):
        choice = input(f"Try to break hash with {mode} ? ")
        choice = True if len(choice)==0 or choice.lower()[0]=='y' else False
        if choice:
            os.system(f"hashcat -a 0 -m {list(modes.values())[index]} --remove --potfile-disable hash.txt crackstation-human-only.txt -o cracked_hashes.txt")
            if os.stat("./hash.txt").st_size != 0:
                print(f"Could not break hash using {mode}") 
            else:
                print("\nCongratulations hash cracked\n")
                with open("cracked_hashes.txt","r") as handle:
                    print(handle.read())
                os.remove("cracked_hashes.txt")
                break
