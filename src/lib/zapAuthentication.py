#!/usr/bin/env python
import urllib.parse
from lib.zapv2 import ZAPv2

class ZapAuthentication(object):

    def __init__(self, zap, targetUrl, username, password, loginPage, logoutPage):
        self.zap=zap
        self.targetUrl=targetUrl
        self.username=username
        self.password=password
        self.loginPage=loginPage
        self.logoutPage=logoutPage
        self.context_id = 1
        self.context_name = 'Attack Context'

    # Use the line below if ZAP is not listening on port 8080, for example, if listening on port 8090
    # zap = ZAPv2(apikey=apikey, proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})

    def set_include_in_context(self):
        exclude_url = self.targetUrl+"/"+self.logoutPage
        include_url = self.targetUrl+"/*"
        self.zap.context.include_in_context(self.context_name, include_url)
        self.zap.context.exclude_from_context(self.context_name, exclude_url)
        print('Configured include and exclude regex(s) in context')


    def set_logged_in_indicator(self):
        logged_in_regex = '\Q<a href="'+self.logoutPage+'">Logout</a>\E'
        self.zap.authentication.set_logged_in_indicator(self.context_id, logged_in_regex)
        print('Configured logged in indicator regex: ')


    def set_form_based_auth(self):
        login_url = self.targetUrl+"/"+self.loginPage
        login_request_data = 'username={%username%}&password={%password%}'
        form_based_config = 'loginUrl=' + urllib.parse.quote(login_url) + '&loginRequestData=' + urllib.parse.quote(login_request_data)
        self.zap.authentication.set_authentication_method(self.context_id, 'formBasedAuthentication', form_based_config)
        print('Configured form based authentication')


    def set_user_auth_config(self):
        user = 'Attack User'

        user_id = self.zap.users.new_user(self.context_id, user)
        user_auth_config = 'username=' + urllib.parse.quote(self.username) + '&password=' + urllib.parse.quote(self.password)
        self.zap.users.set_authentication_credentials(self.context_id, user_id, user_auth_config)
        self.zap.users.set_user_enabled(self.context_id, user_id, 'true')
        self.zap.forcedUser.set_forced_user(self.context_id, user_id)
        self.zap.forcedUser.set_forced_user_mode_enabled('true')
        print('User Auth Configured')
        return user_id


    def start_spider(self, user_id):
        self.zap.spider.scan_as_user(self.context_id, user_id, self.targetUrl, recurse='true')
        print('Started Scanning with Authentication')

    def getAuthenticated(self):
        self.set_include_in_context()
        self.set_form_based_auth()
        self.set_logged_in_indicator()
        user_id_response = self.set_user_auth_config()
        self.start_spider(user_id_response)