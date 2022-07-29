from collections import OrderedDict
from urllib.parse import quote

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptDict, VUL_TYPE
from pocsuite3.lib.utils import random_str


class JenkinsSignup(POCBase):
    vulID = '97018'  # ssvid
    version = '1.0'
    references = ['']
    author = ['fuzzingq']
    createDate = '2022-07-29'
    updateDate = '2022-07-29'
    name = 'jenkins 允许用户注册'
    appName = 'jenkins'
    risk = 'High'
    appVersion = 'all'
    desc = '''jenkins enable /signup'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP


    def _check(self):

        url = self.url.rstrip("/") + "/signup"
        headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6"
        }
        r = requests.get(url, headers=headers)
        if r.status_code == 200 and "/securityRealm/createAccount" in r.text:
            return url
        return False


    def _verify(self):
        result = {}
        p = self._check()
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['URL'] = p
            result['VerifyInfo']['risk'] = self.risk
            result['VerifyInfo']['vul_detail'] = self.desc

        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

register_poc(JenkinsSignup)