#!/usr/bin/python

# Base imports for all integrations, only remove these at your own risk!
import json
import sys
import os
import time
import pandas as pd
from collections import OrderedDict
import re
from integration_core import Integration
import datetime
from IPython.core.magic import (Magics, magics_class, line_magic, cell_magic, line_cell_magic)
from IPython.core.display import HTML
from io import StringIO
from requests import Request, Session

from jupyter_integrations_utility.batchquery import df_expand_col
# Your Specific integration imports go here, make sure they are in requirements!
import jupyter_integrations_utility as jiu
#import IPython.display
from IPython.display import display_html, display, Javascript, FileLink, FileLinks, Image
import ipywidgets as widgets

##custom to elliptic integration
from elliptic_core._version import __desc__

import random
from time import strftime, localtime
import jmespath
from io import BytesIO
import base64

@magics_class
class Elliptic(Integration):
    # Static Variables
    # The name of the integration
    name_str = "elliptic"
    instances = {}
    custom_evars = ["elliptic_conn_default", "elliptic_verify_ssl","elliptic_rate_limit","elliptic_submission_visiblity"]
    # These are the variables in the opts dict that allowed to be set by the user. These are specific to this custom integration and are joined
    # with the base_allowed_set_opts from the integration base

    # These are the variables in the opts dict that allowed to be set by the user. These are specific to this custom integration and are joined
    # with the base_allowed_set_opts from the integration base
    custom_allowed_set_opts = ["elliptic_conn_default","elliptic_verify_ssl","elliptic_rate_limit", "elliptic_submission_visiblity"]

    help_text = ""
    help_dict = {}

    myopts = {}
    myopts['elliptic_conn_default'] = ["default", "Default instance to connect with"]
    myopts['elliptic_verify_ssl'] = [True, "Verify integrity of SSL"]
    myopts['elliptic_rate_limit'] = [True, "Limit rates based on Elliptic user configuration"]

    """
    Key:Value pairs here for APIs represent the type? 
    """

    base_url = "<base_url_here>"

    """
    Syntax is 
    {'command':{'url':'the service url', 'path':'path_for_service',
    'method':'POST', 'parsers':[(pandas_column_name,
    jmespath_parse_expression)]}
        {
            "scan": {'url':base_url,'path': "/scan/", 'method':'POST','parsers':[]},
            "result": {
                'url':base_url,
                'path':"/result/",
                'method':'GET',
                ## column_name & column_value as jmespath valid string
                'parsers':[
                    ("cookies","data.cookies[*].[domain,name,value]"),
                ]
            }
        }
    """

    apis = {}


    # Class Init function - Obtain a reference to the get_ipython()
    def __init__(self, shell, debug=False, *args, **kwargs):
        super(Elliptic, self).__init__(shell, debug=debug)
        self.debug = debug
        #Add local variables to opts dict
        for k in self.myopts.keys():
            self.opts[k] = self.myopts[k]

        self.load_env(self.custom_evars)
        self.parse_instances()
#######################################



    def retCustomDesc(self):
        return __desc__


    def customHelp(self, curout):
        n = self.name_str
        mn = self.magic_name
        m = "%" + mn
        mq = "%" + m
        table_header = "| Magic | Description |\n"
        table_header += "| -------- | ----- |\n"
        out = curout

        qexamples = []
        qexamples.append(["myinstance", "(command)\n(data)", "Command abstracts an endpoint and how the data is sent to it (if applicable)."])
        out += self.retQueryHelp(qexamples)
        return out

    #This function stops the integration for prompting you for username
    #def req_username(self, instance):
    #    bAuth=False
    #    return bAuth

    def customAuth(self, instance):
        result = -1
        inst = None
        if instance not in self.instances.keys():
            result = -3
            print("Instance %s not found in instances - Connection Failed" % instance)
        else:
            inst = self.instances[instance]
        if inst is not None:
            if inst['options'].get('useproxy', 0) == 1:
                myproxies = self.get_proxy_str(instance)
            else:
                myproxies = None

            if inst['enc_pass'] is not None:
                mypass = self.ret_dec_pass(inst['enc_pass'])
            else:
                mypass=None

            #TODO
            #we also need  to figure out how to do this with the secret
            temp = AML(KEY=mypass, secret=mypass)
            inst['session']=temp.client
            inst['session'].proxies=myproxies

            ssl_verify = self.opts['elliptic_verify_ssl'][0]
            if isinstance(ssl_verify, str) and ssl_verify.strip().lower() in ['true', 'false']:
                if ssl_verify.strip().lower() == 'true':
                    ssl_verify = True
                else:
                    ssl_verify = False
            elif isinstance(ssl_verify, int) and ssl_verify in [0, 1]:
                if ssl_verify == 1:
                    ssl_verify = True
                else:
                    ssl_verify = False

            inst['session'].verify=ssl_verify
            result = 0
        return result

    def parse_query(self, query):
        q_items = query.split("\n")
        end_point = q_items[0].strip()
        if len(q_items) > 1:
            end_point_vars = q_items[1].strip()
        elif len(q_items) > 2:
            end_point_vars = list(map(lambda variable : variable.strip(),q_items))
        else:
            end_point_vars = None
        return end_point, end_point_vars


    def validateQuery(self, query, instance):
        bRun = True
        bReRun = False

        if self.instances[instance]['last_query'] == query:
            # If the validation allows rerun, that we are here:
            bReRun = True
        # Example Validation
        # Warn only - Don't change bRun
        # Basically, we print a warning but don't change the bRun variable and the bReRun doesn't matter

        inst = self.instances[instance]
        ep, ep_vars = self.parse_query(query)

        if ep not in self.apis.keys():
            print(f"Endpoint: {ep} not in available APIs: {self.apis.keys()}")
            bRun = False
            if bReRun:
                print("Submitting due to rerun")
                bRun = True
        return bRun

    def _apiFileDownload(self, response, uuid):
        if self.debug:
            print('_apiDOMDownload')
            print(response)
            print(uuid)
        status = -1
        if os.access('.', os.W_OK):
            f = open(f"dom_{uuid}.txt","wb")
            try:
                f.write(response.content)
            except Exception as e:
                print(f"An error has occured:\n{str(e)}")
                print(status=-2)
            finally:
                f.flush()
                f.close()
                status = 0
        else:
            print("Please check that you are in a writeable directory before making this request.") 
        return status 

    def _apiDisplayScreenshot(self, response):
        status = 0
        if self.debug:
            print('_apiDisplayScreenshot')
            print(f"Lenght of content to write: {str(len(response.content))}")
            print("Response content first 100 characters")
            print(f"Print {response.content[0:100]}")
        b64_img = base64.b64encode(response.content).decode()
        try:
            output = f"""
                <img
                    src="data:image/png;base64,{b64_img}"
                />
            """
            display(HTML(output))
        except Exception as e:
            print(f"An error with PIL occured: {str(e)}")
            status = -1
        return status

    def _apiResultParser(self, scan_result, parsers):
        if self.debug:
            print('_apiResultParser')
            print(type(scan_result))
            print(parsers)
        parsed = {}
        for expression in parsers:
            parsed.update({expression[0]:[jmespath.search(expression[1],scan_result.json())]})
        return parsed

    def customQuery(self, query, instance, reconnect=True):
        
        ep, ep_data = self.parse_query(query)
        ep_api = self.apis.get(ep, None)

        if self.debug:
            print(f"Query: {query}")
            print(f"Endpoint: {ep}")
            print(f"Endpoint Data: {ep_data}")
            print(f"Endpoint API Transform: {ep_api}")
            print("Session headers")
            print(self.instances[instance]['session'].headers)
        mydf = None
        status = ""
        str_err = ""
        ##TODO


    def parse_help_text(self):

        help_lines = self.help_text.split("\n")
        bmethods = False
        methods_dict = {}
        method = ""
        method_name = ""
        method_text = []
        inmethod = False
        for l in help_lines:
            if l.find(" |  -------------------------") == 0:
                if inmethod:
                    methods_dict[method_name] = {"title": method, "help": method_text}
                    method = ""
                    method_name = ""
                    method_text = []
                    inmethod = False
                bmethods = False
            if bmethods:
                if l.strip() == "|":
                    continue
                f_l = l.replace(" |  ", "")
                if f_l[0] != ' ':
                    inmethod = True
                    if inmethod:
                        if method_name.strip() != "":
                            if method_name == "__init__":
                                method_name = "API"
                            methods_dict[method_name] = {"title": method, "help": method_text}
                            method = ""
                            method_name = ""
                            method_text = []
                    method = f_l
                    method_name = method.split("(")[0]
                else:
                    if inmethod:
                        method_text.append(f_l)
            if l.find("|  Methods defined here:") >= 0:
                bmethods = True
        self.help_dict = methods_dict

    # This is the magic name.
    @line_cell_magic
    def elliptic(self, line, cell=None):
        if cell is None:
            line = line.replace("\r", "")
            line_handled = self.handleLine(line)
            if self.debug:
                print("line: %s" % line)
                print("cell: %s" % cell)
            if not line_handled: # We based on this we can do custom things for integrations. 
                if line.lower() == "testintwin":
                    print("You've found the custom testint winning line magic!")
                else:
                    print("I am sorry, I don't know what you want to do with your line magic, try just %" + self.name_str + " for help options")
        else: # This is run is the cell is not none, thus it's a cell to process  - For us, that means a query
            self.handleCell(cell, line)

##############################
