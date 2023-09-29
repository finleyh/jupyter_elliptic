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
from requests import JSONDecodeError, Response

from jupyter_integrations_utility.batchquery import df_expand_col
# Your Specific integration imports go here, make sure they are in requirements!
import jupyter_integrations_utility as jiu
#import IPython.display
from IPython.display import display_html, display, Javascript, FileLink, FileLinks, Image
import ipywidgets as widgets

##custom to elliptic integration
from elliptic_core._version import __desc__

import random
import requests
from time import strftime, localtime, sleep
import jmespath
from io import BytesIO
import base64
from elliptic_core.api import API
from IPython.core.debugger import set_trace
requests.packages.urllib3.disable_warnings()

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
    myopts['elliptic_verify_ssl'] = [False, "Verify integrity of SSL"]
    myopts['elliptic_rate_limit'] = [True, "Limit rates based on Elliptic user configuration"]
    myopts['elliptic_batch_wait'] = [3, "Time to wait in seconds between requests to API endpoint."]
    myopts['elliptic_batchsubmit_wait_time'] = [2, "Seconds between batch HTTP requests"]
    myopts['elliptic_batchsubmit_max_file_load'] = [100, "The number of submissions"]
    myopts['elliptic_batchsubmit_error_concat'] = [100, "The length of error messages printed during batchsubmission processing"]
    myopts['elliptic_redirect_wait'] = [5, "Seconds to wait on HTTP30X redirect"]
    myopts['elliptic_resultready_wait_time']=[6, "Seconds between submission and result polling"]
    myopts['elliptic_resultready_wait_attempts']=[6, "How many times to poll results before giving up."]
    myopts['elliptic_submission_privacy'] = ["private", "Default visiblity for submissions to URLScan."]
    myopts['elliptic_submission_country'] = ["US","The country from which the scan should be performed"]
    myopts['elliptic_submission_referer'] = [None, "Override the HTTP referer for this scan"]
    myopts['elliptic_submission_useragent'] = [None, "Override useragent for this scan"]
    myopts['elliptic_nodecode_error'] = [300, "The number of characters to allow before truncating error message strings related to non-decode errors"]
    myopts['elliptic_special_stop_code'] = [[400,429],"Error codes from the web server that a developer may want to respect to take special action."]
    myopts['elliptic_redirect_codes']=[[301,302,308],"Redirect codes that may require special handling by the integration developer"]

    """
    Key:Value pairs here for APIs represent the type? 
    """

    # Class Init function - Obtain a reference to the get_ipython()
    def __init__(self, shell, debug=False, *args, **kwargs):
        super(Elliptic, self).__init__(shell, debug=debug)
        self.debug = debug
        #Add local variables to opts dict
        for k in self.myopts.keys():
            self.opts[k] = self.myopts[k]
        self.API_CALLS = list(filter(lambda func: not func.startswith('_') and hasattr(getattr(API,func),'__call__'), dir(API)))
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
        qexamples.append(["","wallet_analysis\n2a8d1b70-27e2-41c9-8799-7848badd0379\n212c6a69-91d5-4a52-ae16-1b0154d1772c","Given the following Wallet Analysis IDs\nquery the Elliptic Endpoint to retrieve the analysis details."])
        qexamples.append(["","wallet\nbc1pp2xds8sxc4gscuw5hmnwkulmrrl4waw2emfdfx79ct6zra2jkgvqfdjfdx\n1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","This example submits a series of analysis requests for the following wallets.\nThe IDs returned by the API can be used to retrieve the results."])
        qexamples.append(["","transaction --source\ntxid=97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9\nwallet=Ler4HNAEfwYhBmGXcFP2Po1NpRUEiK8km2\nnote=example","Transaction is an odd fish, please reach out to Finley if you want to do this in batch."])
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
                myproxies = self.retProxy(instance)
            else:
                myproxies = None

            print(inst['enc_pass'])

            if inst['enc_pass'] is not None:
                mypass = self.ret_dec_pass(inst['enc_pass'])
            else:
                mypass=None

            ssl_verify = self.opts['elliptic_verify_ssl'][0]
            if isinstance(ssl_verify, str) and ssl_verify.strip().lower() in ['true', 'false','0','1']:
                if ssl_verify.strip().lower() in ['true','1']:
                    ssl_verify = True
                else: 
                    ssl_verify = False
            elif isinstance(ssl_verify, int) and ssl_verify in [0, 1]:
                if ssl_verify == 1:
                    ssl_verify = True
                else:
                    ssl_verify = False

            inst['session']=API(key=inst['user'], secret=mypass,host=inst['host'], port=inst['port'], scheme=inst['scheme'], debug=self.debug, verify=ssl_verify,proxies=myproxies)
            result = 0
        return result
    
    def response_decodes(self, response : Response):
        try:        
            response.json()
        except JSONDecodeError as json_e:
            return False
        return True

    def parse_query(self, query):
        q_items = query.split("\n")
        command = q_items[0].strip().split(" ")
        command = list(filter(None,command))
        end_point_switches = []
        end_point = command[0].lower()
        if len(command) > 1:
            end_point_switches = command[1:]
        if len(q_items[1:]) >=1:
            end_point_vars = list(filter(None,list(map(lambda variable : variable.strip(), q_items[1:]))))
        else:
            end_point_vars = None
        return end_point, end_point_vars, end_point_switches
    def execute_request(self, instance : str, ep : str, data : str, endpoint_doc : dict, polling : bool = False):
        """
        Description
        -----------

        This function makes requests using the Python requests library, and can optionally poll for responses
        
        Parameters
        ----------
        ep : str
            represents a user given command, maps to an endpoint
        ep_data : str|list
            data passed to 'cell' after line, ep
        polling : bool, optional
            If True, polls URLScan results after submission for X attempts by Y
            interval, as defined by myopts['elliptic_resultready_wait_attempts']
            and myopts['elliptic_resultready_wait_time'] respectively
        batching : bool, optional
            If True, tells execute_request NOT to instantiate instance globals
            _dict and _raw for prev_%yourmagic%_%yourinstance%_, presumes you
            will handle the variables downstream as an aggregate

        Output
        ------
        bDecode : bool - bool flag indicating if the 'text' object passed be decoded into a dictionary object using the JSON library
        status : bool - bool flag indicating if response object 'ok' field is True or False
        status_code : int value represents response status code from interacting web server
        text : str - the response content (in decoded text) sent from interacting web server
        content : bytes - raw bytes as provided by the interacting web server
        """

        final_response=None
        try:
            response = getattr(self.instances[instance]['session'],ep)(data)
            final_response = response
        except Exception as e:
            print(f"An error occured while performing {ep} with {data}\n{str(e)}")
            return False, False, None, None, None
        
        if polling and response.ok:
            limit = self.opts['elliptic_resultready_wait_attempts'][0]
            wait = self.opts['elliptic_resultready_wait_time'][0]     
            print(f"""
                Waiting {wait} seconds 
                after each submission to ask {str(self.name_str)} if the results are ready for a 
                maximum of {limit} attempts...
            """)
            # Does this polling endpoint require specific data to poll for response?
            data = response.json().get(endpoint_doc.get('polling_data'),data) 
            # does this polling endpoint require a change in API function to poll for response?
            ep = endpoint_doc.get('polling_endpoint',ep)
            last_response = None
            for i in range(0,limit):
                response = getattr(self.instances[instance]['session'],ep)(data)
                last_response = response
                if response.status_code in self.opts['elliptic_specialstop_code'][0]:
                    break
                if response.status_code in self.opts['elliptic_redirect_codes'][0]:
                    method='GET'
                    api_url=response.headers.get('Location','error')
                    wait = self.opts['elliptic_redirect_wait'][0]
                    response = getattr(API,'get_redirect')(api_url)
                    last_response=response
                    #check for statuscode stop condition
                if response.ok: break
                sleep(wait)
            final_response=last_response
        return self.response_decodes(final_response), final_response.ok, final_response.status_code, final_response.text, final_response.content

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

        if ep not in self.API_CALLS:
            print(f"Endpoint: {ep} not in available API endpoints: [{self.API_CALLS}]")
            bRun = False
            if bReRun:
                print("Submitting due to rerun")
                bRun = True
        
        if hasattr(API,ep):
            if not set(eps).issubset(set(json.loads(getattr(API,ep).__doc__).get('switches'))):
                bRun = False
                print(f"Error: {self.name_str} Instance: {instance} Endpoint: {ep} does not support switch {eps}")
                print(f"Supported switches: {json.loads(getattr(API,ep).__doc__)['switches']}")
        
        return bRun

    
    def customQuery(self, query, instance, reconnect=True):
        ep, ep_data,eps = self.parse_query(query)

        if self.debug:
            print(f"Query: {query}")
            print(f"Endpoint: {ep}")
            print(f"Endpoint Data: {ep_data}")
            print(f"Endpoint API Transform: {ep_api}")

        mydf = None
        status = ""
        str_err = ""
        batch=False
        get_batch=False
        polling = False

        if ep=="help":
            self.call_help(ep_data)
            return mydf, "Success - No Results"
        
        if "-b" in eps or (len(ep_data)>1):
            print("Batch processing enabled")
            batch=True
        
        if "-p" in eps:
            print("Polling enabled")
            polling=True

        try:
            endpoint_doc = json.loads(getattr(API,ep).__doc__)
            if batch and ep in ['submit_wallet','submit_transaction']:
                canDecode, ok, status_code, response_text, response_content = self.execute_request(instance, ep, ep_data, endpoint_doc, polling=polling)
            elif batch and ep in ['get_wallet','get_transaction']:
                temp=[]
                for line in ep_data:
                    canDecode, ok, status_code, response_text, response_content = self.execute_request(instance, ep, line, endpoint_doc, polling=polling)
                    if canDecode and ok:
                        temp.append(json.loads(response_text))
                mydf = pd.DataFrame(temp)
                str_err = "Success - Results"
                return mydf, str_err
            else:
                canDecode, ok, status_code, response_text, response_content = self.execute_request(instance, ep, ep_data[0], endpoint_doc, polling=polling)
            if ok and canDecode:
                if ep=='get_transaction' or ep=='get_wallet':
                    mydf = pd.DataFrame([json.loads(response_text)])
                else:
                    mydf = pd.DataFrame(json.loads(response_text))
                    str_err = "Success - Results"
            elif canDecode:
                mydf = pd.DataFrame(json.loads(response_text))
                str_err = f"Success - Status Code{status_code}"
            else:
                str_err = f"Error - {status_code}: {response_text[:['elliptic_nodecode_error'][0]]}"
                mydf=None

        except Exception as e:
            print(f"Error - {str(e)}")
            mydf = None
            str_err = "Error, {str(e)}"
        return mydf, str_err

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
