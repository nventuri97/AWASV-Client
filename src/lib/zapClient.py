import os, sys, getopt, time, json, signal
from pprint import pprint
from lib.stopException import stopException
from lib.zapv2 import ZAPv2
from lib.zapAuthentication import ZapAuthentication

class ZapClient(object):

    def __init__(self, zapIp, apiKey, proxy=None):
        if proxy is not None:
            self.zap= ZAPv2(ip=zapIp, apikey=apiKey, proxies={'http': 'http://'+proxy, 'https': 'https://'+proxy})
        else:
            self.zap= ZAPv2(ip=zapIp, apikey=apiKey)

        signal.signal(signal.SIGTERM, self.stopSignal)
        signal.signal(signal.SIGINT, self.stopSignal)

        print("Initial ZAP REST Client configuration done!")

    def stopSignal():
        raise stopException


    #----------------------------------------SPIDER BLOCK----------------------------------

    def spider(self, target, context_id=None, user_id=None):
        # The scan returns a scan id to support concurrent scanning
        #if scan is authenticated or not
        if context_id is not None and user_id is not None :
            self.zap.spider.scan_as_user(context_id, user_id, target, recurse='true')
            return self.zap.spider.results()
        else:
            scanID = self.zap.spider.scan(target)

            max_duration=int(self.zap.spider.option_max_duration)
            timeout=None
            if max_duration > 0:
                timeout = time.time() + max_duration   # max duration from now
            while int(self.zap.spider.status(scanID)) < 100:
                if timeout is not None and time.time() > timeout:
                    break
                # Poll the status until it completes
                print('Spider progress %: {}'.format(self.zap.spider.status(scanID)))
                time.sleep(1)
        
        print('Spider has completed!')
        # Prints the URLs the spider has crawled
        print('\n'.join(map(str, self.zap.spider.results(scanID))))
        # If required post process the spider results
        return self.zap.spider.results(scanID)

    def configSpider(self, spiderConfiguration):
        print("Configuring spider")
        if "max-children" in spiderConfiguration:
            self.zap.spider.set_option_max_children(spiderConfiguration["max-children"])
            print(self.zap.spider.option_max_children)
        if "max-depth" in spiderConfiguration:
            self.zap.spider.set_option_max_depth(spiderConfiguration["max-depth"])
        if "max-duration" in spiderConfiguration:
            self.zap.spider.set_option_max_duration(spiderConfiguration["max-duration"])
        if "max-psb" in spiderConfiguration:
            self.zap.spider.set_option_max_parse_size_bytes(spiderConfiguration["max-psb"])
        print("Spider configured")

    #-------------------------------------AJAX SPIDER BLOCK----------------------------------
    def ajaxSpider(self, target, context_id=None):
        if context_id is not None:
            scanID= self.zap.ajaxSpider.scan(target, contextname=context_id)
        else:
            scanID = self.zap.ajaxSpider.scan(target)
        
        max_duration=int(self.zap.ajaxSpider.option_max_duration)
        timeout=None
        if max_duration>0:
            timeout = time.time() + max_duration # max duration from now
        # Loop until the ajax spider has finished or the timeout has exceeded
        while self.zap.ajaxSpider.status == 'running':
            if timeout is not None and time.time() > timeout:
                break
        print('Ajax Spider status ' + self.zap.ajaxSpider.status)
        time.sleep(2)

        print('Ajax Spider completed')
        ajaxResults = self.zap.ajaxSpider.results(start=0, count=10)
        return ajaxResults

    def configAjaxSpider(self, ajaxSpiderConfiguration):
        print("Configuring ajax spider")
        if "max-crawl-depth" in ajaxSpiderConfiguration:
            self.zap.ajaxSpider.set_option_max_crawl_depth(ajaxSpiderConfiguration["max-crawl-depth"])
        if "max-crawl-states" in ajaxSpiderConfiguration:
            self.zap.ajaxSpider.set_option_max_crawl_states(ajaxSpiderConfiguration["max-crawl-states"])
        if "max-duration" in ajaxSpiderConfiguration:
            self.zap.ajaxSpider.set_option_max_duration(ajaxSpiderConfiguration["max-duration"])
        if "browser-windows" in ajaxSpiderConfiguration:
            self.zap.ajaxSpider.set_option_number_of_browsers(ajaxSpiderConfiguration["browser-windows"])
        if "event-wait" in ajaxSpiderConfiguration:
            self.zap.ajaxSpider.set_option_event_wait(ajaxSpiderConfiguration["event-wait"])
        if "reload-time" in ajaxSpiderConfiguration:
            self.zap.ajaxSpider.set_option_reload_wait(ajaxSpiderConfiguration["reload-time"])
        print("Ajax spider configured")

    #-------------------------------------PASSIVE SCAN BLOCK----------------------------------

    def passiveScan(self):
        while int(self.zap.pscan.records_to_scan) > 0:
            # Loop until the passive scan has finished
            print('Records to passive scan : ' + self.zap.pscan.records_to_scan)
            time.sleep(2)

        print('Passive Scan completed')

        # Print Passive scan results/alerts
        print('Hosts: {}'.format(', '.join(self.zap.core.hosts)))
        print('Alerts: ')
        pprint(self.zap.core.alerts())

    def configPassiveScan(self, passiveScanConfiguration):
        print("Configuring passive scanner")
        if "enabled" in passiveScanConfiguration:
            self.zap.pscan.set_enabled(passiveScanConfiguration["enabled"])
        if "scope-only" in passiveScanConfiguration:
            self.zap.pscan.set_scan_only_in_scope(passiveScanConfiguration["scope-only"])
        if "max-alert" in passiveScanConfiguration:
            self.zap.pscan.set_max_alerts_per_rule(passiveScanConfiguration["max-alert"])
        if "alert-treshold" in passiveScanConfiguration:
            self.zap.pscan.set_scanner_alert_threshold(passiveScanConfiguration["alert-treshold"])
        print("Passive scanner configured")

    #-------------------------------------ACTIVE SCAN BLOCK----------------------------------

    def activeScan(self, target, context_id=None):
        scanID = self.zap.ascan.scan(url=target, contextid=context_id)
        print(scanID)
        max_duration=int(self.zap.ascan.option_max_scan_duration_in_mins)
        timeout=None
        if max_duration is not None:
            timeout = time.time() + max_duration   # max duration from now
        while int(self.zap.ascan.status(scanID)) < 100:
            if timeout is not None and time.time() > timeout:
                break
            # Loop until the scanner has finished
            print('Scan progress %: {}'.format(self.zap.ascan.status(scanID)))
            time.sleep(5)

        print('Active Scan completed')
        # Print vulnerabilities found by the scanning
        print('Hosts: {}'.format(', '.join(self.zap.core.hosts)))
        print('Alerts: ')
        pprint(self.zap.core.alerts(baseurl=target))

    def configActiveScan(self, activeScanConfiguration):
        print("Configuring active scanner")
        if "max-duration" in activeScanConfiguration:
            self.zap.ascan.set_option_max_scan_duration_in_mins(activeScanConfiguration["max-duration"])
        if "max-rule-duration" in activeScanConfiguration:
            self.zap.ascan.set_option_max_rule_duration_in_mins(activeScanConfiguration["max-rule-duration"])
        if "host-scan" in activeScanConfiguration:
            self.zap.ascan.set_option_host_per_scan(activeScanConfiguration["host-scan"])
        if "thread-host" in activeScanConfiguration:
            self.zap.ascan.set_option_thread_per_host(activeScanConfiguration["thread-host"])
        if "delay" in activeScanConfiguration:
            self.zap.ascan.set_option_delay_in_ms(activeScanConfiguration["delay"])
        print("Active scanner configured")

    #---------------------------------EXECUTION BLOCK---------------------------------------
    def execute(self, configAttack):
        if ('urlTarget' or 'strength') not in configAttack:
            print("URL Target or strength parameter are missing, but they are mandatory")
            return None

        target=configAttack["urlTarget"]
        strength=configAttack["strength"]
        auth=False

        if 'authenticated' in configAttack:
            print("Authenticated scan will be performed")
            authenticated=configAttack["authenticated"]
            auth=True
            if ('username' or 'passwd' or 'login-page' or 'logout-page') not in authenticated:
                print("If the analysis is authenticated insert in attackFile both username, password, login page than logout page")
                return None

            username=authenticated["username"]
            passwd=authenticated["passwd"]
            loginPage=authenticated["login-page"]
            logoutPage=authenticated["logout-page"]
            print("Configuring authentication parameters")
            zapAuth=ZapAuthentication(self.zap, target, username, passwd, loginPage, logoutPage)
            (context_id, user_id)=zapAuth.getAuthenticated()

        if "configuration" in configAttack:
            print("Analysis with personalized configuration and "+strength+" strength at target "+target)
            configuration=configAttack["configuration"]
            if "spider" in configuration:
                self.configSpider(configuration["spider"])
            if "ajax-spider" in configuration:
                self.configAjaxSpider(configuration["ajax-spider"])
            if "passive-scan" in configuration:
                self.configPassiveScan(configuration["passive-scan"])
            if "active-scan" in configuration:
                self.configActiveScan(configuration["active-scan"])
        else:
            print("Analysis with default configuration and "+strength+" strength at target "+target)

        try:
            if strength=="low":
                #Spider return a list of URLs that can be process
                if not auth:
                    spiderResults=self.spider(target)
                    ajaxResults=self.ajaxSpider(target)
                else:
                    spiderResult=self.spider(target, context_id, user_id)
                    ajaxResults=self.ajaxSpider(target, context_id)
            elif strength=="medium":
                if not auth:
                    spiderResults=self.spider(target)
                    ajaxResults=self.ajaxSpider(target)
                else:
                    spiderResult=self.spider(target, context_id, user_id)
                    ajaxResults=self.ajaxSpider(target, context_id)
                self.passiveScan()
            elif strength=="high":
                if not auth:
                    spiderResults=self.spider(target)
                    ajaxResults=self.ajaxSpider(target)
                    self.passiveScan()
                    self.activeScan(target)
                else:
                    spiderResult=self.spider(target, context_id, user_id)
                    ajaxResults=self.ajaxSpider(target, context_id)
                    self.passiveScan()
                    self.activeScan(target, context_id)
                
            else:
                print("Strength value not permitted")
                return None

            return self.zap.core.htmlreport()

        except stopException: 
            if int(self.zap.spider.status()) < 100:
                self.zap.spider.stop_all_scans()
            if self.zap.ajaxSpider.status=='running':
                self.zap.spider.stop_all_scans()
            if int(self.zap.ascan.status()) < 100:
                self.zap.ascan.stop_all_scans()
            print("Analysis interrupted by user")

            return self.zap.core.htmlreport()