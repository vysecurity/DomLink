#!/usr/bin/env python3

from configparser import RawConfigParser
from argparse import ArgumentParser
from requests import get
import sys
import os.path
import urllib.request, urllib.parse, urllib.error
import logging


__version__ = '0.2'


def set_log_level(args_level):
    if args_level is None:
        args_level = 0
    log_level = logging.ERROR
    if args_level == 1:
        log_level = logging.WARN
    elif args_level == 2:
        log_level = logging.INFO
    elif args_level > 2:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)


def get_args():
    parser = ArgumentParser()
    parser.add_argument('domain', help='Domain to perform DomLink Discovery on')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-A', '--api', help='https://www.whoxy.com API key')
    parser.add_argument('-v', '--verbose', action='count')
    parser.add_argument('-C', '--companies', action='store_true',
            help='recursively search companies')
    parser.add_argument('-E', '--emails', action='store_true',
            help='recursively search emails')
    parser.add_argument('-D', '--domains', action='store_true',
            help='recursively search domains')
    return parser.parse_args()


def read_key_from_config():
    config = RawConfigParser()
    file = config.read(os.path.join(os.path.dirname(sys.argv[0]), 'domLink.cfg'))
    if file:
        return config.get('API_KEYS', 'whoxy')
    else:
        logging.error('Could not find \'domLink.cfg\' and no API key was defined.')
        exit()

def check_balance(base_url):
    mode = {'lookup': True, 'history': True, 'reverse': True}
    url = '{}&account=balance'.format(base_url)
    content = get(url).json()

    logging.info('Checking account balance')

    if (content['status'] == 0):
        logging.error('WHOIS lookup failed, {}'.format(content['status_reason']))
        exit()
    elif (content['status'] == 1):
        if (content['live_whois_balance'] == 0 and content['whois_history_balance'] == 0 and content['reverse_whois_balance'] == 0):
            logging.error('Zero API queries left. Please recharge.')
            exit()
        elif (content['live_whois_balance'] == 0):
            logging.warning('WHOIS lookup credits have been exhausted. Lookup API queries will be skipped.')
            mode['lookup'] = False
        elif (content['whois_history_balance'] == 0):
            logging.warning('WHOIS history credits have been exhausted. History API queries will be skipped.')
            mode['history'] = False
        elif (content['reverse_whois_balance'] == 0):
            logging.warning('Reverse WHOIS credits have been exhausted. Reverse API queries will be skipped.')
            mode['reverse'] = False
    else:
        logging.error('WHOIS lookup failed, {}'.format(content['status_reason']))
        exit()
    return mode

def parse_whois(base_url, domain):
    logging.info('Performing WHOIS lookup on {}'.format(domain))

    emails, companies, domains = {}, {}, {domain: False}
    url = '{}&whois={}'.format(base_url, domain)
    content = get(url).json()

    for record in ['registrant', 'administrative', 'technical']:
        record = '{}_contact'.format(record)
        email = content.get(record, {}).get('email_address', '').lower()
        company = content.get(record, {}).get('company_name', '')
        if email and (email != 'redacted for privacy') and ('*' not in email):
            logging.debug('domain: adding email {}'.format(email))
            emails[email] = True
        if company and company != 'REDACTED FOR PRIVACY':
            logging.debug('domain: adding email {}'.format(email))
            companies[company] = True
    return {'emails': emails, 'companies': companies, 'domains': domains}


def parse_history(base_url, domain):
    logging.info('Performing WHOIS history lookup on {}'.format(domain))

    emails, companies, domains = {}, {}, {domain: False}
    url = '{}&history={}'.format(base_url, domain)
    content = get(url).json()

    if (content['total_records_found'] >= 1):
        for record in content['whois_records']:
            for entry in ['registrant', 'administrative', 'technical']:
                entry = '{}_contact'.format(entry)
                email = record.get(entry, {}).get('email_address', '').lower()
                company = record.get(entry, {}).get('company_name', '')
                if email and (email != 'redacted for privacy') and ('*' not in email):
                    logging.debug('domain: adding email {}'.format(email))
                    emails[email] = True
                if company and company != 'REDACTED FOR PRIVACY':
                    logging.debug('domain: adding email {}'.format(email))
                    companies[company] = True
    return {'emails': emails, 'companies': companies, 'domains': domains}


def recursive_search(base_url, search, find, page=1, pages=9999):
    emails, companies, domains = {}, {}, {}
    while page <= pages:
        url = '{}&reverse=whois&{}={}&mode=mini&page={}'.format(
                base_url, search, find, page)
        content = get(url).json()
        total_pages = content.get('total_pages', 1)
        if total_pages < pages:
            pages = total_pages
        if content.get('status', 0) == 1:
            for result in content['search_result']:
                domain = result.get('domain_name', '')
                company = result.get('company_name', '')
                email = result.get('email_address', '')
                if domain:
                    logging.debug('{}={} adding email {}'.format(search, find, domain))
                    domains[domain] = True
                if company:
                    logging.debug('{}={} adding email {}'.format(search, find, company))
                    companies[company] = True
                if email and (email != 'redacted for privacy') and ('*' not in email):
                    logging.debug('{}={} adding email {}'.format(search, find, email))
                    emails[email] = True
        page += 1
    return {'domains': domains, 'emails': emails, 'companies': companies}


def merge(source, destination):
    for key, value in list(source.items()):
        if isinstance(value, dict):
            # get node or create one
            node = destination.setdefault(key, {})
            merge(value, node)
        else:
            destination[key] = value
    return destination


def query_yes_no(question, default='yes'):
    '''Ask a yes or no question'''
    valid = {'yes': True, 'y': True, 'ye': True,
            'no': False, 'n': False}
    if default is None:
        prompt = ' [y/n] '
    elif default == 'yes':
        prompt = ' [Y/n] '
    elif default == 'no':
        prompt = ' [y/N] '
    else:
        raise ValueError('invalid default answer: {}'.format(default))

    while True:
        choice = input(question + prompt).lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            print('Please respond with \'yes\' or \'no\'(or \'y\' or \'n\').\n')


def banner():
    print ("")
    print ("DomLink Domain Discovery Tool")
    print ("Author: Vincent Yiu (@vysecurity)")
    print ("Contributors: Jan Rude (@whoot); John Bond (@b4ldr)")
    print ("https://www.github.com/vysec/DomLink")
    print ("Version: {}".format(__version__))
    print ("")

def main():
    banner()
    
    args = get_args()
    set_log_level(args.verbose)
    api_key = args.api if args.api else read_key_from_config()
    blacklist = {'domains': set(), 'emails': set(), 'companies': set()}
    base_url = 'https://api.whoxy.com/?key={}'.format(api_key)

    if '.' not in args.domain:
        logging.error('It\'s probably unlikely that the target is a whole TLD')
        exit()

    balance = check_balance(base_url)
    if (balance['lookup']):
        results = parse_whois(base_url, args.domain)
    if (balance['history']):
        results = merge(results, parse_history(base_url, args.domain))

    while any(list(results['domains'].values()) + 
        list(results['companies'].values()) + 
        list(results['emails'].values())):
        if args.domains:
            for domain, check in list(results['domains'].items()):
                if not check:
                    continue
                check = query_yes_no('Do you want to check "{}"'.format(domain))
                if check:
                    results = merge(results, parse_whois(base_url, domain))
                    if (balance['history']):
                        results = merge(results, parse_history(base_url, domain))
                    check = False
                else:
                    blacklist['domains'].add(domain)
                results['domains'][domain] = check
        else:
            results['domains'] = dict.fromkeys(results['domains'], False)
        if args.companies:
            for company, check in list(results['companies'].items()):
                if balance['reverse'] is True:
                    if not check:
                        continue
                    check = query_yes_no('Do you want to check "{}"'.format(company))
                    if check:
                        results = merge(results, recursive_search(base_url, 'company', urllib.parse.quote_plus(company)))
                        check = False
                    else:
                        blacklist['companies'].add(company)
                else:
                    check = False
                results['companies'][company] = check
        else:
            results['companies'] = dict.fromkeys(results['companies'], False)
        if args.emails:
            for email, check in list(results['emails'].items()):
                if balance['reverse'] is True:
                    if not check:
                        continue
                    check = query_yes_no('Do you want to check "{}"'.format(email))
                    if check:
                        results = merge(results, recursive_search(base_url, 'email', email))
                        check = False
                    else:
                        blacklist['emails'].add(email)
                else:
                    check = False
                results['emails'][email] = check
        else:
            results['emails'] = dict.fromkeys(results['emails'], False)
    output = '''
### Company Names:
{}\n
### Domain Names:
{}\n
### Email Addresses:
{}'''.format(
            '\n'.join(
                [k for k in list(results['companies'].keys()) if k not in blacklist['companies']]),
            '\n'.join(
                [k for k in list(results['domains'].keys()) if k not in blacklist['domains']]),
            '\n'.join(
                [k for k in list(results['emails'].keys()) if k not in blacklist['emails']]))
    print(output)
    if args.output:
        with open(args.output, 'w') as text_file:
            text_file.write(output)


if __name__ == '__main__':
    main()

