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
from elliptic import AML
from IPython.core.debugger import set_trace

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

    apis = {
        'wallet':{
            'batch_path':'/v2/wallet',
            'path':'/v2/wallet/synchronous',
            'method':'POST',
            'payload':{
                'subject':{
                'type':'address',
                'asset':'holistic',
                'blockchain':'holistic',
                'hash':'<PLACEHOLDER>'
            },
            'type':'wallet_exposure'
            }
        },
        'transaction':{
            'batch_path':'/v2/analyses',
            'path':'/v2/analyses/synchronous',
            'method':'POST',
            'switches':['--destination','--source'],
            'payload':{
               'subject':{
                'type':'transaction',
                'output_type':'address',
                'asset':'holistic',
                'blockchain':'holistic',
                'hash':'<PLACEHOLDER>',
                'output_type':'address'
            },
            'type':'<DEST_OR_SOURCE>',#destination_of_funds/source_of_funds
            'customer_reference':'<REFERENCE>' 
            }
        },
        'analysis':{
            'batch_path':'/v2/analyses?page=1&per_page=500&subject_type=',
            'path':'/v2/analyses/',
            'method':'GET',
            'switches':['--transaction', '--wallet'],
        }
    }


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

            print(inst['enc_pass'])

            if inst['enc_pass'] is not None:
                mypass = self.ret_dec_pass(inst['enc_pass'])
            else:
                mypass=None

            inst['session']=AML(key=inst['user'], secret=mypass).client
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
        command = q_items[0].strip().split(" ")
        command = list(set(list(filter(None,command))))
        end_point_switches = []
        end_point = command[0].lower()
        if len(command) > 1:
            end_point_switches = command[1:]
        if len(q_items[1:]) >=1:
            end_point_vars = list(set(list(filter(None,list(map(lambda variable : variable.strip(), q_items[1:]))))))
        else:
            end_point_vars = None
        return end_point, end_point_vars, end_point_switches


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
        ep, ep_vars, eps = self.parse_query(query)

        if ep not in self.apis.keys():
            print(f"Endpoint: {ep} not in available APIs: {self.apis.keys()}")
            bRun = False
            if bReRun:
                print("Submitting due to rerun")
                bRun = True
        
        return bRun


    def customQuery(self, query, instance, reconnect=True):
        ep, ep_data,eps = self.parse_query(query)
        ep_api = self.apis.get(ep, None)
        if self.debug:
            print(f"Query: {query}")
            print(f"Endpoint: {ep}")
            print(f"Endpoint Data: {ep_data}")
            print(f"Endpoint API Transform: {ep_api}")
        mydf = None
        status = ""
        str_err = ""
        batch=False

        try:
            set_trace()
            if len(ep_data)>1 or (ep=='analysis' and len(ep_data<1)): 
                batch=True
            if self.apis[ep]['method'] == 'POST':
                post_body = self.create_post_body(self.apis[ep]['payload'], ep_data, batch=batch)
            else:
                post_body = None

            if batch:
                url_path = self.apis[ep]['batch_url']
            else:
                url_path = self.apis[ep]['path'] + ep_data.strip()

            response = self.make_request(instance, self.apis[ep]['method'], url_path, data=post_body)
            if response.status_code==200:
                if ep=='analysis' and batch:
                    results = []
                    results = results + response.json().get('items')
                    while response.json().get('page')<response.json().get('pages'):
                        response = self.make_request(instance, self.apis[ep]['method'], url_path, data=post_body)
                        if response.status_code==200:
                            results = results+response.json().get('items')
                    mydf = pd.DataFrame(results)
                else:
                    mydf = pd.DataFrame(response.json())
            else:
                str_err = "Error -"

        except Exception as e:
            print(f"Error - {str(e)}")
            mydf = None
            str_err = "Error, {str(e)}"
        return mydf, str_err

    def create_post_body(self, payload, ep_data, batch=False):
        payloads = None
        if batch:
            payloads = []
            for data in ep_data:
                payloads = payloads+payload['subject'].update({'hash':data})
        else:
            payloads = payload['subject'].update({'hash':ep_data})
        return payloads

    def make_request(self, instance, method, path, data,verify=False):
        response = self.instances[instance]['session'].request(
            'method',
            path,
            json=data,
            verify=verify
        )
        return response

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
