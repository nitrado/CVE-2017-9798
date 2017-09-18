import argparse
import fnmatch
import os
import sys
import re

def main():
    parser = argparse.ArgumentParser(description='Checking for CVE-2017-9798.')
    parser.add_argument('--path', help='Path to check for .htaccess files.', required=True)

    args = parser.parse_args()

    okay = True

    find_regex = re.compile("^<limit (.*)>$", flags=re.IGNORECASE)
    allowed = [
        'GET',
        'PUT',
        'POST',
        'DELETE',
        'CONNECT',
        'OPTIONS',
        'PATCH',
        'PROPFIND',
        'PROPPATCH',
        'MKCOL',
        'COPY',
        'MOVE',
        'LOCK',
        'UNLOCK',
        'HEAD'
    ]

    files = []
    for root, dirnames, filenames in os.walk(args.path):
        for filename in fnmatch.filter(filenames, '.htaccess'):
            files.append(os.path.join(root, filename))

    for file in files:
        print("Checking file: " + file)
        with open(file) as f:
            for line in f.readlines():
                matches = find_regex.match(line)
                if matches:
                    for value in matches.group(1).split(' '):
                        if not value.strip() in allowed:
                            print("Value " + value.strip() + " is not allowed for <Limit>.")
                            okay = False

    if not okay:
        print('\033[91m' + "Your system is affected!" + '\033[00m')
        sys.exit(1)

    print('\x1b[6;30;42m' + "Your system seems to be okay." + '\x1b[0m')

if __name__ == "__main__":
    main()
