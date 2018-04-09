import ConfigParser
import argparse
import os
import sys
import requests
import json
import urllib

parser = argparse.ArgumentParser(description='DomLink Discovery')
parser.add_argument('-d', '--domain', help='Domain to perform DomLink Discovery on')
parser.add_argument('-o', '--output', help='Output file')
args = parser.parse_args()
config = ConfigParser.RawConfigParser()
config.read('domLink.cfg')
api_key = config.get('API_KEYS', 'whoxy')

VERSION = "0.1.1"

company_names = []
company_emails = []
company_domains = []

blocked_names = []
blocked_emails = []

bChanged = False
iteration = 1

def banner():
	print "DomLink Domain Discovery Tool"
	print "Author: Vincent Yiu (@vysecurity)"
	print "https://www.github.com/vysec/DomLink"
	print "Version: %s" % VERSION
	print ""

def enum(domain):
	global bChange, iteration

	bChanged = False
	url = "http://api.whoxy.com/?key=%s&whois=%s" % (api_key,args.domain)
	r = requests.get(url)
	content = json.loads(r.text)

	print "[*] Performing WHOIS lookup on %s" % args.domain

	if (content["status"] != 1):
		print "[!] WHOIS lookup failed, your API key is probably invalid or credits have been exhausted"

	try:
		if not (content["registrant_contact"]["company_name"] in company_names):
			company_names.append(content["registrant_contact"]["company_name"])

		if not (content["registrant_contact"]["email_address"] in company_emails):
			company_emails.append(content["registrant_contact"]["email_address"])

		if not (content["administrative_contact"]["company_name"] in company_names):
			company_names.append(content["administrative_contact"]["company_name"])

		if not (content["administrative_contact"]["email_address"] in company_emails):
			company_emails.append(content["administrative_contact"]["email_address"])

		if not (content["technical_contact"]["company_name"] in company_names):
			company_names.append(content["technical_contact"]["company_name"])

		if not (content["technical_contact"]["email_address"] in company_emails):
			company_emails.append(content["technical_contact"]["email_address"])
	except:
		bChanged = True

	print ""
	print "-------------------"
	print "[*] Unique Company names:"

	for company_name in company_names:
		print company_name

	print ""
	print "[*] Unique Company emails:"

	for company_email in company_emails:
		print company_email

	print ""
	bChange = True

def expand():
	global bChange,iteration


	print "[*] Performing Reverse WHOIS lookup"

	# Company names first
	
	for company_name in company_names:
		pages = 9999
		cur_page = 1
		
		while (cur_page-1 < pages):
			print "%s out of %s" %(cur_page, pages)
			url = "http://api.whoxy.com/?key=%s&reverse=whois&company=%s&mode=mini&page=%s" % (api_key, urllib.quote(company_name), cur_page)

			r = requests.get(url)
			content = json.loads(r.text)
			#print content
			if content["status"] == 1:
				pages = content["total_pages"]
				for result in content["search_result"]:
					try:
						if not (result["domain_name"] in company_domains):
							company_domains.append(result["domain_name"])
						if not(result["company_name"] in company_names):
							company_names.append(result["company_name"])
						if not(result["email_address"].lower() in company_emails) and not(result["email_address"].lower() in blocked_emails):
							bAdd = raw_input("[*] Do you want to add '%s' as a company email? (Y/n):" % result["email_address"]).upper()
							if bAdd == "" or bAdd == "Y":
								bAdd = "Y"
							else:
								bAdd = "N"

							if bAdd == "Y":
								bChange = True
								company_emails.append(result["email_address"].lower())
							else:
								blocked_emails.append(result["email_address"].lower())

					except:
						continue
			cur_page += 1

	print company_emails
	print company_names

	# Emails now
	
	for company_email in company_emails:
		pages = 9999
		cur_page = 1
		
		while (cur_page-1 < pages):

			print "%s out of %s" %(cur_page, pages)
 			url = "http://api.whoxy.com/?key=%s&reverse=whois&email=%s&mode=mini&page=%s" % (api_key, urllib.quote(company_email), cur_page)

			r = requests.get(url)
			content = json.loads(r.text)
			#print content
			if content["status"] == 1:
				pages = content["total_pages"]
				for result in content["search_result"]:
					try:
						if not (result["domain_name"] in company_domains):
							company_domains.append(result["domain_name"])
						if not(result["company_name"].lower() in company_names):
							print "[*] Added company name: '%s'" % result["company_name"]
							
						if not(result["email_address"].lower() in company_emails):
							company_emails.append(result["email_address"])
							
					except:
						continue
			cur_page += 1


if __name__ == '__main__':
	banner()
	if args.domain == None:
		print "[!] No domain specified"
		exit()
	elif (not "." in args.domain):
		print "[!] It's probably unlikely that the target is a whole TLD"
		exit()

	enum(args.domain)
	expand()

	if args.output != None:
		file = open(args.output, 'w+')

		file.write("[*] Company Names\r\n")
		file.writelines([x+os.linesep for x in company_names])
		

		file.write("[*] Company Emails\r\n")
		file.writelines([x+os.linesep for x in company_emails])

		file.write("[*] Associated Domains\r\n")
		file.writelines([x+os.linesep for x in company_domains])

		file.close()

		print "[*] Written to file %s" % args.output
	else:
		print "[*] Company Names"
		for company_name in company_names:
			print company_name

		print "[*] Company Emails"

		for company_email in company_emails:
			print company_emails

		print "[*] Associated Domains"

		for domain in company_domains:
			print domain

