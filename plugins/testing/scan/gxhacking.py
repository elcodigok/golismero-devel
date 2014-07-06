#!/usr/bin/env python
# -*- coding: utf-8 -*-

__license__ = """
GoLismero 2.0 - The web knife - Copyright (C) 2011-2014

Golismero project site: http://golismero-project.com
Golismero project mail: contact@golismero-project.com

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

from golismero.api.config import Config
from golismero.api.data import discard_data
from golismero.api.data.information.fingerprint import WebServerFingerprint
from golismero.api.data.resource.url import URL
from golismero.api.data.vulnerability import UncategorizedVulnerability
from golismero.api.data.vulnerability.information_disclosure.url_disclosure import UrlDisclosure
from golismero.api.logger import Logger
from golismero.api.net.http import HTTP
from golismero.api.net.web_utils import ParsedURL, urljoin, get_error_page, download
from golismero.api.text.matching_analyzer import MatchingAnalyzer, get_diff_ratio
from golismero.api.text.wordlist import WordListLoader

from golismero.api.plugin import TestingPlugin
from functools import partial

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET


#------------------------------------------------------------------------------
class PredictablesDisclosureBruteforcer(TestingPlugin):


    #--------------------------------------------------------------------------
    def get_accepted_types(self):
        return [URL]


    #--------------------------------------------------------------------------
    def run(self, info):

        m_url = info.url

        Logger.log("GXHacking against: %s" % m_url)
        Logger.log_more_verbose("Start to process URL: %r" % m_url)

        # Server specified by param?
        webserver_finger = Config.plugin_args.get("server_banner", None)
        if webserver_finger:
            server_canonical_name = webserver_finger
            servers_related = []  # Set with related web servers
        else:
            # User fingerprint info
            webserver_finger = info.get_associated_informations_by_category(WebServerFingerprint.information_type)
            if webserver_finger:
                webserver_finger = webserver_finger.pop()

                server_canonical_name = webserver_finger.canonical_name
                servers_related = webserver_finger.related  # Set with related web servers

        # Find XML files
        new_file = find_xml_files(m_url)

        wordlist = set()

        # Common wordlists
        try:
            w = Config.plugin_extra_config["common"]
            wordlist.update([l_w for l_w in w.itervalues()])
        except KeyError:
            Logger.log_error("Can't load common wordlists")

        # There is fingerprinting information?
        if webserver_finger:

            #
            # Load wordlists
            #
            wordlist_update = wordlist.update

            # Wordlist of server name
            try:
                w = Config.plugin_extra_config["%s_predictables" % server_canonical_name]
                wordlist_update([l_w for l_w in w.itervalues()])
            except KeyError:
                Logger.log_error("Can't load predictables wordlists for server: '%s'." % server_canonical_name)

            # Wordlist of related with the server found
            try:
                for l_servers_related in servers_related:
                    w = Config.plugin_extra_config["%s_predictables" % l_servers_related]
                    wordlist_update([l_w for l_w in w.itervalues()])
            except KeyError, e:
                Logger.log_error("Can't load wordlists predictables wordlists for related webserver: '%s'" % e)

        # Load content of wordlists
        urls = set()
        #Logger.log(urls)

        for l_w in new_file:
            try:
                l_w = l_w[1:] if l_w.startswith("/") else l_w
                tmp_u = urljoin(m_url, l_w)
            except ValueError, e:
                Logger.log_error("Failed to parse key, from wordlist, '%s'" % tmp_u)
                continue

            urls.add(tmp_u)

        for l_w in wordlist:
            # Use a copy of wordlist to avoid modify the original source
            l_loaded_wordlist = WordListLoader.get_wordlist_as_list(l_w)

            for l_wo in l_loaded_wordlist:
                try:
                    l_wo = l_wo[1:] if l_wo.startswith("/") else l_wo
                    tmp_u = urljoin(m_url, l_wo)
                except ValueError, e:
                    Logger.log_error("Failed to parse key, from wordlist, '%s'" % tmp_u)
                    continue

                urls.add(tmp_u)

        Logger.log_verbose("Loaded %s URLs to test." % len(urls))

        # Generates the error page
        error_response = get_error_page(m_url)
        
        # Create the matching analyzer
        try:
            store_info = MatchingAnalyzer(error_response.raw_data, min_ratio=0.0)
        except ValueError, e:
            Logger.log_error("There is not information for analyze when creating the matcher: '%s'" % e)
            return

        # Create the partial funs
        _f = partial(process_url,
                     4,
                     get_http_method(m_url),
                     store_info,
                     self.update_status,
                     len(urls))

        # Process the URLs
        for i, l_url in enumerate(urls):
            _f((i, l_url))

        # Generate and return the results.
        return generate_results(store_info.unique_texts)


#------------------------------------------------------------------------------
def find_xml_files(url):
    new_file = []
    for file_name in ['execute.xml', 'DeveloperMenu.xml']:
        url_check = url[1:] if url.startswith("/") else url
        tmp_u = urljoin(url_check, file_name)
        p = HTTP.get_url(tmp_u, use_cache=False, method="GET")
        if p.status == "200":
            file_save = download(tmp_u)
            tree = ET.fromstring(file_save.raw_data)
            try:
                for links in tree.findall('Object'):
                    Logger.log(links.find('ObjLink').text)
                    new_file.append(links.find('ObjLink').text)
            except Exception:
                ##raise # XXX DEBUG
                pass
    
    return new_file


#------------------------------------------------------------------------------
def process_url(risk_level, method, matcher, updater_func, total_urls, url):
    """
    Checks if an URL exits.

    :param risk_level: risk level of the tested URL, if discovered.
    :type risk_level: int

    :param method: string with HTTP method used.
    :type method: str

    :param matcher: instance of MatchingAnalyzer object.
    :type matcher: `MatchingAnalyzer`

    :param updater_func: update_status function to send updates
    :type updater_func: update_status

    :param total_urls: total number of URL to globally process.
    :type total_urls: int

    :param url: a tuple with data: (index, the URL to process)
    :type url: tuple(int, str)
    """
    i, url = url

    updater_func((float(i) * 100.0) / float(total_urls))
    # Logger.log_more_verbose("Trying to discover URL %s" % url)

    # Get URL
    p = None
    try:
        p = HTTP.get_url(url, use_cache=False, method=method)
        if p:
            discard_data(p)
    except Exception, e:
        Logger.log_error_more_verbose("Error while processing: '%s': %s" % (url, str(e)))

    # Check if the url is acceptable by comparing
    # the result content.
    #
    # If the maching level between the error page
    # and this url is greater than 52%, then it's
    # the same URL and must be discarded.
    #
    #Logger.log(p.status)
    if p and p.status == "200":

        # If the method used to get URL was HEAD, get complete URL
        if method != "GET":
            try:
                p = HTTP.get_url(url, use_cache=False, method="GET")
                if p:
                    discard_data(p)
            except Exception, e:
                Logger.log_error_more_verbose("Error while processing: '%s': %s" % (url, str(e)))

        Logger.log(matcher.analyze(p.raw_response, url=url, risk=0.62))
        Logger.log_more_verbose("Discovered partial url: '%s'" % url)


#------------------------------------------------------------------------------
def get_http_method(url):
    """
    This function determinates if the method HEAD is available. To do that, compare between two responses:
    - One with GET method
    - One with HEAD method

    If both are seem more than 90%, the response are the same and HEAD method are not allowed.
    """

    m_head_response = HTTP.get_url(url, method="HEAD")  # FIXME handle exceptions!
    discard_data(m_head_response)

    m_get_response  = HTTP.get_url(url)  # FIXME handle exceptions!
    discard_data(m_get_response)

    # Check if HEAD reponse is different that GET response, to ensure that results are valids
    return "HEAD" if HTTP_response_headers_analyzer(m_head_response.headers, m_get_response.headers) < 0.90 else "GET"


#------------------------------------------------------------------------------
# HTTP response analyzer.

def HTTP_response_headers_analyzer(response_header_1, response_header_2):
    """
    Does a HTTP comparison to determinate if two HTTP response matches with the
    same content without need the body content. To do that, remove some HTTP headers
    (like Date or Cache info).

    Return a value between 0-1 with the level of difference. 0 is lowest and 1 the highest.

    - If response_header_1 is more similar to response_header_2, value will be near to 100.
    - If response_header_1 is more different to response_header_2, value will be near to 0.

    :param response_header_1: text with http response headers.
    :type response_header_1: http headers

    :param response_header_2: text with http response headers.
    :type response_header_2: http headers
    """

    m_invalid_headers = [
        "Date",
        "Expires",
        "Last-Modified",
    ]

    m_res1 = ''.join([ "%s:%s" % (k,v) for k,v in response_header_1.iteritems() if k not in m_invalid_headers ])
    m_res2 = ''.join([ "%s:%s" % (k,v) for k,v in response_header_2.iteritems() if k not in m_invalid_headers ])

    return get_diff_ratio(m_res1, m_res2)


#------------------------------------------------------------------------------
def generate_results(unique_texts):
    """
    Generates a list of results from a list of URLs as string format.

    :param unique_texts: list with a list of URL as string.
    :type unique_texts: list(URL)

    :return: a list of URL/UrlDiclosure.
    :type: list(URL|UrlDiclosure)
    """
    # Analyze resutls
    m_results        = []
    m_results_append = m_results.append
    #kwargs = {"level": "informational"}

    for l_match in unique_texts:
        #
        # Set disclosure vulnerability
        l_url                      = URL(l_match.url)
        l_vuln                     = UrlDisclosure(l_url)
        #l_vuln                     = UncategorizedVulnerability(l_url, **kwargs)

        # Set impact
        l_vuln.risk                = l_match.risk

        # Store
        m_results_append(l_url)
        m_results_append(l_vuln)

    return m_results
