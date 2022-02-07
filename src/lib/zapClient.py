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

    def spider(self, zap, target, context_id, user_id):
        # The scan returns a scan id to support concurrent scanning
        #if scan is authenticated or not
        if context_id is not None and user_id is not None :
            scanID = zap.spider.scan(context_id, user_id, target, recurse='true')
        else:
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

    def configSpider(self, spiderConfiguration):
        print("Configuring spider")
        if "max-children" in spiderConfiguration:
            self.zap.spider.set_option_max_children(spiderConfiguration["max-children"], self.zap.__apikey)
        if "max-depth" in spiderConfiguration:
            self.zap.spider.set_option_max_depth(spiderConfiguration["max-depth"], self.zap.__apikey)
        if "max-duration" in spiderConfiguration:
            self.zap.spider.set_option_max_duration(spiderConfiguration["max-duration"], self.zap.__apikey)
        if "max-psb" in spiderConfiguration:
            self.zap.spider.set_option_max_parse_size_bytes(spiderConfiguration["max-psb"], self.zap.__apikey)
        print("Spider configured")

    def ajaxSpider(self, zap, target, context_id, user_id):
        #Not implemented
        pass

    def configAjaxSpider(self, ajaxSpiderConfiguration):
        print("Configuring ajax spider")
        if "max-crawl-depth" in ajaxSpiderConfiguration:
            self.zap.ajaxSpider.set_option_max_crawl_depth(ajaxSpiderConfiguration["max-crawl-depth"], self.zap.__apikey)
        if "max-crawl-states" in ajaxSpiderConfiguration:
            self.zap.ajaxSpider.set_option_max_crawl_states(ajaxSpiderConfiguration["max-crawl-states"], self.zap.__apikey)
        if "max-duration" in ajaxSpiderConfiguration:
            self.zap.ajaxSpider.set_option_max_duration(ajaxSpiderConfiguration["max-duration"], self.zap.__apikey)
        if "browser-windows" in ajaxSpiderConfiguration:
            self.zap.ajaxSpider.set_option_number_of_browsers(ajaxSpiderConfiguration["browser-windows"], self.zap.__apikey)
        if "event-wait" in ajaxSpiderConfiguration:
            self.zap.ajaxSpider.set_option_event_wait(ajaxSpiderConfiguration["event-wait"], self.zap.__apikey)
        if "reload-time" in ajaxSpiderConfiguration:
            self.zap.ajaxSpider.set_option_reload_wait(ajaxSpiderConfiguration["reload-time"], self.zap.__apikey)
        print("Ajax spider configured")

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
            auth=True
            if ('username' or 'passwd' or 'login-page' or 'logout-page') not in authenticated:
                 sys.exit("If the analysis is authenticated insert in attackFile both username, password, login page than logout page")

            username=authenticated["username"]
            passwd=authenticated["passwd"]
            loginPage=authenticated["login-page"]
            logoutPage=authenticated["logout-page"]
            print("Configuring authentication parameters")
            zapAuth=ZapAuthentication(self.zap, target, username, passwd, loginPage, logoutPage)
            (context_id, user_id)=zapAuth.getAuthenticated()

        if strength=="low":
            #Spider return a list of URLs that can be process
            if not auth:
                spiderResult=self.spider(self.zap, target)
            else:
                spiderResult=self.spider(context_id, user_id, self.zap, target)
        elif strength=="medium":
            pass
        elif strength=="high":
            pass
        elif strength=="personalized":
            configuration=configAttack["configuration"]
            if "spider" in configuration:
                self.configSpider(configuration["spider"])
            if "ajax-spider" in configuration:
                self.configAjaxSpider(configuration["ajax-spider"])
            if "passive-scanner" in configuration:
                self.configPassiveScanner(configuration["passive-scanner"])
            if "active-scanner" in configuration:
                self.configActiveScanner(configuration["active-scanner"])
        else:
            print("Strength value not permitted")
            
        print("Analysis with strength "+strength+" at address "+target+" starts")

        print('Spidering target {}'.format(target))
        
        # TODO: Explore the Application more with Ajax Spider or Start scanning the application for vulnerabilities