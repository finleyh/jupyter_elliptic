from elliptic import AML


class API(object):
    def __init__(self, secret : str, key : str, host : str, scheme : str = 'https://', port : int = 443, verify : bool = False, debug : bool = False, proxies : dict = {}):
        self.session = AML(key=key, secret=secret)
        self.scheme = scheme
        self.base_url = scheme + host + ':' + str(port)
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
    

    def submit_wallet(self, data : str , asset : str = 'holistic', blockchain : str = 'blockchain', batch : bool = False):
        if not batch:
            path = '/v2/wallet/synchronous'
        else:
            path = '/v2/wallet'
        method = 'POST'
        payload = {
            'subject':{
                  'type':'address',
                  'asset':asset,
                  'blockchain':blockchain,
                  'hash':data,
            },
            'type':'wallet_exposure'
        }
        return self.__results(method, path, payload)


    def get_wallet(self, data : str):
        method = 'GET'
        path = f'/v2/wallet/{data}'
        payload = None
        return self.__results(method, path, payload)

    def submit_transaction(self, data : str, type : str, customer_reference : str):
        path  = '/v2/analyses'
        method = 'POST'
        payload = {
            'subject':{
                'type':'transaction',
                'output_type':'address',
                'asset':'holistic',
                'blockchain':'holistic',
                'hash':data,
                'output_type':'address'
            },
            'type':type,
            'customer_reference':customer_reference
        }
        return self.__results(method, path, payload)

    def get_transaction(self, data : str):
        method = 'GET'
        path = f'/v2/analyses/{data}'
        payload=None
        return self.__results(method, path, payload)