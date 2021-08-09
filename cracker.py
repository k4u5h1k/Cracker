#!/usr/bin/env python3
import os
import sys
import requests
import subprocess
from shutil import which
from identifier import HashID

if not which("hashcat"):
    print("hashcat not installed, installing manually")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "hashcat"])

try:
    from tqdm import *
except:
    print("tqdm not installed, installing manually")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "tqdm"])
    from tqdm import *

def main(tocrack, proj_dir):
    tocrack = sys.argv[1]
    proj_dir = sys.path[0]
    hashfile = os.path.join(proj_dir,"hash.txt")
    crackedfile = os.path.join(proj_dir,"cracked_hashes.txt")
    wordlist = os.path.join(proj_dir,"wordlist.txt")

    with open(hashfile, "w+") as handle:
        handle.write(tocrack)

    hashid = HashID()
    modes = hashid.identifyHash(tocrack)

    if len(modes) > 0:
        for index,mode in enumerate(modes):
            choice = input(f"Try to break hash with {mode}? ")
            choice = True if len(choice)==0 or choice.lower()[0]=='y' else False
            if choice:
                os.system((f'hashcat -a 0 -m {list(modes.values())[index]} --remove --potfile-disable "{hashfile}"'
                    f' "{wordlist}" -o "{crackedfile}"'))
                if os.stat("hash.txt").st_size != 0:
                    print(f"Could not break hash using {mode}") 
                else:
                    print("\nCongratulations hash was cracked!\n")
                    print("==================================")
                    with open("cracked_hashes.txt","r") as handle:
                        result = handle.readline().split(":")
                        print(f'{result[0]}:\033[31m{result[1]}\033[0m', end='')
                    print("==================================")
                    os.remove("cracked_hashes.txt")
                    break

if __name__ == '__main__':
    if len(sys.argv)==1:
        print(('Usage:'
        'python3 cracker.py hash'))
        sys.exit(0)

    if not os.path.exists("wordlist.txt"):
        choice = input("Wordlist does not exist, download (280MB) and install automatically? ")
        choice = True if len(choice)==0 or choice.lower()[0]=='y' else False
        if choice:
            url = "https://download.g0tmi1k.com/wordlists/large/crackstation-human-only.txt.gz"
            print(f"Downloading wordlist from {url} :")
            with requests.get(url ,stream=True) as r:
                total = 280000000
                with open("wordlist.txt","wb+") as wordlist:
                   progress = tqdm(total=total) 
                   for chunk in r.iter_content(chunk_size=1024*8):
                       wordlist.write(chunk)
                       progress.update(len(chunk))
            progress.clear()
            progress.close()
            print("\nWordlist downloaded!")
        else:
            print(("In that case go ahead and download a wordlist yourself and place it"
                  "in the same directory as cracker.py with the name wordlist.txt!"))
            sys.exit(0)
    main(sys.argv[1], sys.path[0])
