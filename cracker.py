#!/usr/bin/env python3
import os
import sys
import requests
import subprocess
from shutil import which
from identifier import HashID

if not which("hashcat"):
    shouldInstall = input("Hashcat not installed, install via pip? ")
    shouldInstall = True if len(install_choice)==0 or install_choice.lower()[0]=='y' else False
    if shouldInstall:
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
    rule = os.path.join(proj_dir,"myrule.rule")

    with open(hashfile, "w+") as handle:
        handle.write(tocrack)

    hashid = HashID()
    modes = hashid.identifyHash(tocrack)

    use_rules = input("Use rules? ")
    rules_choice = True if len(use_rules)==0 or use_rules.lower()[0]=='y' else False

    # a => hash mode
    # b => rule set
    # c => hash file
    # d => wordlist
    # e => outfile
    if rules_choice:
        getcommand = lambda a, b, c, d, e: f'hashcat -a 0 -m {a} -r {b} --remove --potfile-disable "{c}" "{d}" -o "{e}"'
    else:
        getcommand = lambda a, c, d, e: f'hashcat -a 0 -m {a} --remove --potfile-disable "{c}" "{d}" -o "{e}"'

    if len(modes) > 0:
        for index,mode in enumerate(modes):
            shouldProceed = input(f"Try to break hash with {mode}? ")
            shouldProceed = True if len(shouldProceed)==0 or shouldProceed.lower()[0]=='y' else False
            if shouldProceed:

                if rules_choice:
                    os.system(getcommand(list(modes.values())[index], rule, hashfile, wordlist, crackedfile))
                else:
                    os.system(getcommand(list(modes.values())[index], hashfile, wordlist, crackedfile))

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
        wordlistChoice = input("Wordlist does not exist, download (280MB) and install automatically? ")
        wordlistChoice = True if len(wordlistChoice)==0 or wordlistChoice.lower()[0]=='y' else False
        if wordlistChoice:
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
