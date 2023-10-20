from elliptic import AML
import requests
import re
from itertools import product

class API(object):
    def __init__(self, secret : str, key : str, host : str, scheme : str = 'https://', port : int = 443, verify : bool = False, debug : bool = False, proxies : dict = {}):
        self.session = AML(key=key, secret=secret).client
        self.scheme = scheme
        self.base_url = scheme +'://'+ host + ':' + str(port)
        self.session.verify = verify
        self.session.proxies = proxies
        self.debug = debug
    
    def __results(self, method, path, json):
        try:
            full_url = self.base_url + path
        except Exception as e:
            print("Error:")
            print(type(e))
            print(str(e))
        finally:
            if self.debug:
                print(f'Attempted {method} to path {path} with data {json}')
        return self.session.request(method, full_url, json=json)
    
    def __parse_input(self, data, expression):
        pattern = re.compile(expression)
        return pattern.search(data)
    
    def submit_transaction(self, data : str , blockchain : str = 'holistic', asset : str = 'holistic'):
        """{"switches":["-p"], "polling_endpoint":"get_transaction", "polling_data":"id"}"""
        try:
            transaction_hashes = self.__parse_input('\n'.join(data), r'tx_hashes=(?P<hash>.*?)\n').group('hash').split(',')
            wallet_hashes = self.__parse_input('\n'.join(data), r'wallet_hashes=(?P<hash>.*?)\n').group('hash').split(',')
            customer_reference = self.__parse_input('\n'.join(data), r'(?:ref)|(?:reference)|(?:notes?)=(?P<note>.*?)$').group('note')
        except Exception as e:
            print("When submitting transactions for analysis, you must include\ntx_hashes=tx,hashes,here\nwallet_hash=wallet,hashes,here")
            return
        if len(transaction_hashes) > 1 and len(wallet_hashes)>1 and len(transaction_hashes)!=len(wallet_hashes):
            print("Error - ")
            print("You can provide 1:M wallet:tx or tx:wallet")
            print("You can provide 1:1 wallet_id:transaction_id")
            print("We can't interpret M:N where M!=N")
            return None
        path = '/v2/analyses'
        method = 'POST'
        payload = []
        for wallet_and_tx in product(wallet_hashes,transaction_hashes):
            payload = payload+[{
                'subject':{
                    'type':'transaction',
                    'output_type':'address',
                    'asset':asset,
                    'blockchain':blockchain,
                    'hash':wallet_and_tx[1],
                    'output_address':wallet_and_tx[0]
                },
                'type':'source_of_funds',
                'customer_reference':customer_reference
            },{
                'subject':{
                    'type':'transaction',
                    'output_type':'address',
                    'asset':asset,
                    'blockchain':blockchain,
                    'hash':wallet_and_tx[1],
                    'output_address':wallet_and_tx[0]
                },
                'type':'destination_of_funds',
                'customer_reference':customer_reference
            }
            ]
        return self.__results(method, path, payload)

    def get_transaction(self, data : str, batch : bool = False):
        """{"switches":[]}"""
        method = 'GET'
        path = f'/v2/analyses/{data}'
        payload=None
        return self.__results(method, path, payload)
    
    def get_redirect(self, url):
        """{"switches":[]}"""
        print(f'{self.get_redirect.__name__} called on: {url}')
        method = 'GET'
        payload = None
        return self.__results(method, url, json=payload)

    def submit_wallet(self, data : str , asset : str = 'holistic', blockchain : str = 'holistic'):
        """{"switches":["-p"], "polling_endpoint":"get_wallet","polling_data":"id"}"""
        method = 'POST'
        path = '/v2/wallet'
        payload=[]
        for line in data:
                payload.append({
                    'subject':{
                        'type':'address',
                        'asset':asset,
                        'blockchain':blockchain,
                        'hash':line,
                    },
                    'type':'wallet_exposure'
                })
        return self.__results(method, path, payload)

    def get_wallet(self, data : str, batch : bool = False):
        """{"switches":[]}"""
        method = 'GET'
        path = f'/v2/wallet/{data}'
        payload = None
        return self.__results(method, path, payload)

