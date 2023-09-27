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
