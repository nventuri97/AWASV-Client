import os, sys, getopt, time, json
from lib.zapv2 import ZAPv2
from lib.zapAuthentication import ZapAuthentication

class ZapClient(object):

    def __init__(self, zapIp, apiKey, proxy):
        if proxy is not None:
            self.zap= ZAPv2(ip=zapIp, apikey=apiKey, proxies={'http': 'http://'+proxy, 'https': 'https://'+proxy})
        else:
            self.zap= ZAPv2(ip=zapIp, apikey=apiKey)
        print("Initial ZAP REST Client configuration done!")

    def spider(self, zap, target):
        # The scan returns a scan id to support concurrent scanning
        scanID = zap.spider.scan(target)
        while int(zap.spider.status(scanID)) < 100:
            # Poll the status until it completes
            print('Spider progress %: {}'.format(zap.spider.status(scanID)))
            time.sleep(1)
        

        print('Spider has completed!')
        # Prints the URLs the spider has crawled
        print('\n'.join(map(str, zap.spider.results(scanID))))
        # If required post process the spider results
        return zap.spider.results(scanID)

    def execute(self, configAttack):
        ipTarget=configAttack["ipTarget"]
        strength=configAttack["strength"]
        if 'initial-page' in configAttack:
            initialPage=configAttack["initial-page"]
            target = 'http://'+ipTarget+'/'+initialPage
        else:
            target = 'http://'+ipTarget

        if 'authenticated' in configAttack:
            print("Authenticated scan will be performed")
            authenticated=configAttack["authenticated"]
            if ('username' or 'passwd' or 'login-page' or 'logout-page') not in authenticated:
                 sys.exit("If the analysis is authenticated insert in attackFile both username, password, login page than logout page")

            username=authenticated["username"]
            passwd=authenticated["passwd"]
            loginPage=authenticated["login-page"]
            logoutPage=authenticated["logout-page"]
            print("Configuring authentication parameters")
            zapAuth=ZapAuthentication(self.zap, target, username, passwd, loginPage, logoutPage)
            zapAuth.getAuthenticated()

            
        print("Analysis with strength "+strength+" at address "+target+" starts")

        print('Spidering target {}'.format(target))
        
        #Spider return a list of URLs that can be process
        spiderResult=self.spider(self.zap, target)
        # TODO: Explore the Application more with Ajax Spider or Start scanning the application for vulnerabilities