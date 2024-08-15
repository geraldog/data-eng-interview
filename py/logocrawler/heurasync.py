# Heurasync Sonic
#
# Fast Async Logo Crawler Powered by Simple Deduction (heuristics)
# by Geraldo Nascimento <geraldogabriel@gmail.com>
#
# Copyright - 2024
#

import lxml.html
import asyncio
import aiosonic
from urllib.parse import urlparse
from urllib.parse import urljoin
from urllib.parse import unquote
import binascii
import re
import functools
import sys

async def decode_blob(blob_string, url):
    blob = ''
    if blob_string.startswith("data:text/css"):
        blob = blob_string[13:]
        comma = blob.find(",")
        header = None

        if comma > -1:
            header = blob[:comma]
            blob = blob[comma + 1:]
        
        split_header = None
        if header is not None:
            has_semicolon = header.find(";")
            if has_semicolon > -1:
                split_header = header.split(";")
            if split_header is not None:
                if "base64" in split_header:
                    logo = None
                    for x in range(0, 10):
                       try:
                           logo = binascii.a2b_base64(blob + '=' * x)
                           if logo is not None:
                               return logo.decode('utf-8')
                       except Exception as err_nested:
                           if x == 9:
                               sys.stderr.write("\nPassed Exception: " + type(err_nested).__name__ + ": " + str(err_nested) + " | " + url + "\n")
                           pass
                return None

            elif split_header is None and has_semicolon == -1:
                return blob
        return None

    elif blob_string.startswith("data:text/javascript"):
        blob = blob_string[20:]
        comma = blob.find(",")
        header = None

        if comma > -1:
            header = blob[:comma]
            blob = blob[comma + 1:]
        
        split_header = None
        if header is not None:
            has_semicolon = header.find(";")
            if has_semicolon > -1:
                split_header = header.split(";")
            if split_header is not None:
                if "base64" in split_header:
                    logo = None
                    for x in range(0, 10):
                       try:
                           logo = binascii.a2b_base64(blob + '=' * x)
                           if logo is not None:
                               return logo.decode('utf-8')
                       except Exception as err_nested:
                           if x == 9:
                               sys.stderr.write("\nPassed Exception: " + type(err_nested).__name__ + ": " + str(err_nested) + " | " + url + "\n")
                           pass
                return None

            elif split_header is None and has_semicolon == -1:
                return blob
    else:
        return None

async def decode_and_write_blob(blob_string, url):
    extension = None
    blob = ''
    if blob_string.startswith("data:image/"):
        blob = blob_string[11:]
        comma = blob.find(",")
        header = None

        if comma > 2:
            header = blob[:comma]
            blob = blob[comma + 1:]
        
        split_header = None
        if header is not None:
            has_semicolon = header.find(";")
            if has_semicolon > 2:
                split_header = header.split(";")
            if split_header is not None:
                if split_header[0] == "svg+xml":
                    extension = "svg"
                elif split_header[0] == "webp":
                    extension = "webp"
                elif split_header[0] == "png":
                    extension = "png"
                elif split_header[0] == "jpeg":
                    extension = "jpg"
                elif split_header[0] == "gif":
                    extension = "gif"
                else:
                    return None

            elif split_header is None and has_semicolon == -1:
                if header == "svg+xml":
                    extension = "svg"
                elif header == "webp":
                    extension = "webp"
                elif header == "png":
                    extension = "png"
                elif header == "jpeg":
                    extension = "jpg"
                elif header == "gif":
                    extension = "gif"
                else:
                    return None

            if extension is None:
                return None

            if split_header is not None and "base64" in split_header:
                logo = None
                written_img = False
                for x in range(0, 10):
                   try:
                       logo = binascii.a2b_base64(blob + '=' * x)
                       if logo is not None:
                           coro_write_img = asyncio.to_thread(writeout_bin_img, logo, url, None, "." + extension)
                           written_img = await coro_write_img
                   except asyncio.TimeoutError:
                       sys.stderr.write("\nPassed Timeout: " + url + "\n")
                       pass
                   except Exception as err_nested:
                       if x == 9:
                           sys.stderr.write("\nPassed Exception: " + type(err_nested).__name__ + ": " + str(err_nested) + " | " + url + "\n")
                       pass
                if written_img is True:
                    return extension

            elif extension == 'svg' and split_header is None:
                logo = None
                written_img = False
                try:
                    logo = unquote(blob)
                    if logo is not None:
                        coro_write_img = asyncio.to_thread(writeout_svg, logo, url, True)
                        written_img = await coro_write_img
                except asyncio.TimeoutError:
                    sys.stderr.write("\nPassed Timeout: " + url + "\n")
                    pass
                except Exception as err_nested:
                    sys.stderr.write("\nPassed Exception: " + type(err_nested).__name__ + ": " + str(err_nested) + " | " + url + "\n")
                    pass
                if written_img is True:
                    return extension

        else:
           return None
    else:
        return None

def extract_logo_from_css(style, response_url_string, home_link_class_for_css):
    urls = []
    background_image_regex = re.compile("url\\(([^)]+)\\)")
    class_regex = re.compile("}([^{]+){")
    url_matches = background_image_regex.finditer(style)
    if url_matches is not None:
         for url in url_matches:
             backtrack = 0
             while backtrack < 1000:
                 class_match = class_regex.search(style[url.start() - backtrack:url.end()])
                 if class_match is not None:
                      for found_class in class_match.group(1).split(" "):
                          urls.append([url.group(1).lstrip('"').rstrip('"').lstrip("\'").rstrip("\'"), found_class])
                          backtrack = 1001
                 backtrack += 10
             if backtrack != 1001:
                 urls.append([url.group(1).lstrip('"').rstrip('"').lstrip("\'").rstrip("\'"), ""])
    if urls == []:
        return None
    return urls

def extract_logo_from_script(script, response_url_string, home_link_class_for_css):
    images = []
    script_image_regex = re.compile('(["\'`])([^"\'`]+)(\\.svg|\\.webp|\\.png|\\.jpg|\\.jpeg|\\.gif)')
    image_matches = script_image_regex.finditer(script)
    if image_matches is not None:
        for url in image_matches:
            images.append(url.group(2) + url.group(3))
    if images == []:
        return None
    return images

def writeout_bin_img(response_body, url, img_url, ext):
    site = urlparse(url)
    matched_file_ext = None
    hostname_stripped = re.sub('^www.','', site.hostname, count=1)
    if ext is None:
        matched_file_ext = re.findall("\\.(svg|webp|png|jpg|jpeg|gif)", img_url)
    else:
        with open("logos/" + hostname_stripped[0] + "/" + hostname_stripped + ext, "wb+") as svg_file:
            svg_file.seek(0)
            svg_file.write(response_body)
            return True
    if matched_file_ext:
        with open("logos/" + hostname_stripped[0] + "/" + hostname_stripped + "." + matched_file_ext[-1], "wb+") as svg_file:
            svg_file.seek(0)
            svg_file.write(response_body)
            return True
    return False
    
def writeout_svg(inlined_svg, site, correct):
    site_parsed = urlparse(site)
    hostname_stripped = re.sub('^www.','', site_parsed.hostname, count=1)
    if correct is True:
        with open("logos/" + hostname_stripped[0] + "/" + hostname_stripped + ".svg", "w+") as svg_file:
            svg_file.seek(0)
            svg_file.write(inlined_svg)
            return True
        
    if "xmlns" not in inlined_svg.attrib.keys():
        inlined_svg.attrib['xmlns'] = "http://www.w3.org/2000/svg"
     
    with open("logos/" + hostname_stripped[0] + "/" + hostname_stripped + ".svg", "w+") as svg_file:
        svg_file.seek(0)
        svg_file.write(lxml.html.tostring(inlined_svg, pretty_print=True, encoding='UTF-8').decode("utf-8"))
        return True

def sum_partial_stats(task):
     global no_of_tried_urls
     global list_of_stats
     no_of_tried_urls += 1
     if task.cancelled():
         return
     stats = task.result()
     if stats is not None:
         list_of_stats[1] = list_of_stats[1] + stats[1]
         list_of_stats[2] = list_of_stats[2] + stats[2]
         list_of_stats[3] = list_of_stats[3] + stats[3]
         list_of_stats[4] = list_of_stats[4] + stats[4]
         list_of_stats[5] = list_of_stats[5] + stats[5]
         list_of_stats[6] = list_of_stats[6] + stats[6]
         list_of_stats[7] = list_of_stats[7] + stats[7]

         if (no_of_tried_urls % 100 == 0):
             final_stats = list_of_stats
             no_of_network_exceptions = final_stats[1]
             no_of_parsing_exceptions = final_stats[2]
             no_of_heuristic_fails = final_stats[3]
             no_of_too_big_html = final_stats[4]
             no_of_http_errors = final_stats[5]
             no_of_proposed_logos = final_stats[6]
             no_of_inlined_svgs = final_stats[7]

             sys.stderr.write("\n---Partial Statistics ---\n")
             sys.stderr.write(str(no_of_tried_urls) + " URLs visitation attempts\n")
             sys.stderr.write(str(no_of_network_exceptions) + " Network Exceptions occurred\n")
             sys.stderr.write(str(no_of_parsing_exceptions) + " Parsing Exceptions occurred\n")
             sys.stderr.write(str(no_of_heuristic_fails) + " Failed Heuristic Detections\n")
             sys.stderr.write(str(no_of_too_big_html) + " Too Big or 0-bytes HTMLs\n")
             sys.stderr.write(str(no_of_http_errors) + " Total HTTP(S) errors\n")
             sys.stderr.write(str(no_of_proposed_logos) + " Proposed Logos\n")
             sys.stderr.write(str(no_of_inlined_svgs) + " Inlined SVGs\n\n")

async def download_and_deduce(client, input_url, refreshed, cookies):
    no_of_network_exceptions = 0
    no_of_parsing_exceptions = 0
    no_of_heuristic_fails = 0
    no_of_too_big_html = 0
    no_of_http_errors = 0
    no_of_proposed_logos = 0
    no_of_inlined_svgs = 0
    no_of_excessive_redirects = 0
    no_of_general_errors = 0
    no_of_cancelled_tasks = 0

    if cookies is None:
        headers = {
              'User-Agent': "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
                  }
    else:
        headers = {
              'User-Agent': "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
              'Cookies': cookies,
                  }

    if refreshed > 30:
        no_of_excessive_redirects += 1
        return [0, 0, 0, 0, 0, 0, 0, 0]

    global background_downloads

    try:
        response = ""
        try:
            if input_url not in background_downloads:
                background_downloads.add(input_url)
                response = await client.get(url=input_url, headers=headers, follow=False)
            else:
                return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
                
        except asyncio.TimeoutError:
            no_of_network_exceptions += 1
            sys.stderr.write("aiosonic Timeout: " + input_url + "\n")
            sys.stdout.flush()
            return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
        except Exception as err:
            no_of_network_exceptions += 1
            sys.stderr.write("aiosonic Error: " + type(err).__name__ + ": " + str(err) + " for " + input_url + "\n")
            sys.stdout.flush()
            return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
        background_downloads.discard(input_url)
        if type(response) is not aiosonic.HttpResponse:
            no_of_network_exceptions += 1
            sys.stderr.write("Exception caught: " + str(response) + " for " + input_url + "\n")
            sys.stdout.flush()
            return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
        elif response.status_code >= 200 and response.status_code < 300:
            page_parsed = []
            no_of_links = 0
            try:
                to_parse = await response.text()
            except asyncio.TimeoutError:
                no_of_network_exceptions += 1
                sys.stderr.write("aiosonic Timeout: " + input_url + "\n")
                sys.stdout.flush()
                return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
            except Exception as err:
                no_of_network_exceptions += 1
                sys.stderr.write("aiosonic Read/Decode Error: " + type(err).__name__ + ": " + str(err) + " for " + input_url + "\n")
                sys.stdout.flush()
                return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
        else:
            if response.status_code >= 300 and response.status_code < 400:
                await response.content()
                if "LOCATION" in response.headers.keys():
                    cookies = ""
                    if "cookies" in headers.keys():
                        cookies = headers['cookies']
                    if response.cookies is not None:
                        cookies_matches = re.finditer("Set-Cookie: ([^;]+;)", response.cookies.output())
                        if cookies_matches is not None:
                            for cookie in cookies_matches:
                                cookies += " " + cookie.group(1) 
                    location_header_split = response.headers['location']
                    parsed_location = urlparse(location_header_split)
                    final_location = location_header_split
                    if parsed_location.netloc == "":
                        final_location = urljoin(input_url, final_location)
    
                    return await download_and_deduce(client, final_location, refreshed + 1, cookies.lstrip(" ").rstrip(";"))
            no_of_http_errors += 1
            sys.stderr.write("HTTP Error " + str(response.status_code) + ": " + input_url + "\n")
            sys.stdout.flush()
            return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
        if len(to_parse) > 20000000 or len(to_parse) == 0:
            no_of_too_big_html += 1
            sys.stdout.flush()
            return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
        try:
            # unlike what you may hear, this is safe to do
            # because lxml frees the GIL
            coro_parse_html = asyncio.to_thread(lxml.html.fromstring,to_parse)
            page_parsed = await coro_parse_html
        except Exception as err:
            no_of_parsing_exceptions += 1
            possible_logo_imgs = re.finditer('["\'][^"\']+\\.(jpeg|jpg|png|svg|webp|gif)["\']', to_parse)
            if possible_logo_imgs:
                for logo_img_match in possible_logo_imgs:
                    file_name = to_parse[logo_img_match.start() + 1:logo_img_match.end() - 1]
                    sys.stderr.write(input_url + " Parsing Exception: " + type(err).__name__ + ": " + str(err) + " | regex deduced image: " + file_name + "\n")
                    if "logo" in file_name.lower():
                        logo_url = file_name
                        parsed_file_name = urlparse(file_name)
                        if parsed_file_name.netloc == "":
                            base_url = urlparse(input_url)
                            base_url = base_url.scheme + "://" + base_url.netloc
                            logo_url = urljoin(base_url, file_name)
                        no_of_proposed_logos += 1
                        sys.stdout.flush()
    
                        if logo_url.startswith("data:image/"):
                            success = await decode_and_write_blob(logo_url, input_url)
                            if success is not None:
                                url_parsed = urlparse(input_url)
                                print(input_url + ',' + "./logos/" + url_parsed.hostname + "." + success)
                                return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
                        unicode_escaped_regex = re.compile("\\\\u[0-9a-fA-F]{4}")
                        urlencoded_regex = re.compile("%[0-9a-fA-F]{2}")
    
                        if unicode_escaped_regex.search(logo_url):
                            logo_url = logo_url.encode().decode('unicode_escape')
    
                        if urlencoded_regex.search(logo_url):
                            logo_url = unquote(logo_url)
    
                        if logo_url.startswith("//"):
                            logo_url = "http:" + logo_url.attrib['src']
    
                        print(input_url + ',' + logo_url)
    
                        img_response = ""
    
                        try:
                            if input_url not in background_downloads:
                                background_downloads.add(logo_url)
                                img_response = await client.get(url=logo_url, headers=headers, follow=True)
                            else:
                                pass
                        except asyncio.TimeoutError:
                            sys.stderr.write("\nPassed Timeout: " + logo_url + "\n")
                            pass
                        except Exception as err_nested:
                            sys.stderr.write("\nPassed Exception: " + type(err_nested).__name__ + ": " + str(err_nested) + " | " + logo_url + "\n")
                            pass
                        background_downloads.discard(logo_url)
                        if type(img_response) == aiosonic.HttpResponse:
                            visit = True
                            if "CONTENT-TYPE" in img_response.headers.keys():
                                if "text/html" in img_response.headers['Content-Type']:
                                    visit = False
                            if img_response.status_code >= 200 and img_response.status_code < 300 and visit:
                                try:
                                    coro_write_img = asyncio.to_thread(writeout_bin_img, await img_response.content(), input_url, logo_url, None)
                                    await coro_write_img
                                except asyncio.TimeoutError:
                                    sys.stderr.write("\nPassed Timeout: " + logo_url + "\n")
                                    pass
                                except Exception as err_nested:
                                    sys.stderr.write("\nPassed Exception: " + type(err_nested).__name__ + ": " + str(err_nested) + " | " + logo_url + "\n")
                                    pass
                        return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
            return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
        parsed_base_href = urlparse(input_url)
        page_parsed.make_links_absolute(parsed_base_href.scheme + "://" + parsed_base_href.hostname, resolve_base_href=True)
    
        meta_refresh = page_parsed.xpath('//meta[@http-equiv="refresh"]')
        new_homepage = ""
        if meta_refresh != [] and refreshed < 3:
            address = re.search('url=',meta_refresh[0].attrib['content'])
            if address:
                new_homepage = meta_refresh[0].attrib['content'][address.start() + 4:]
                new_page_parsed = urlparse(new_homepage)
                if new_page_parsed.netloc == "":
                    new_homepage = parsed_base_href.scheme + "://" + parsed_base_href.netloc + "/" + new_homepage
                sys.stderr.write("META Refresh: " + new_homepage + "\n")
        if new_homepage != "":
            cookies = None
            if "cookies" in headers.keys():
                cookies = headers['cookies']
            return await download_and_deduce(client, new_homepage, refreshed + 1, cookies)
    
        unicode_escaped_regex = re.compile("\\\\u[0-9a-fA-F]{4}")
        urlencoded_regex = re.compile("%[0-9a-fA-F]{2}")
    
        normal_base_url = parsed_base_href.scheme + "://" + parsed_base_href.hostname
        www_normal_base_url = parsed_base_href.scheme + "://" + "www." + parsed_base_href.hostname
    
        subdomain_base_url = parsed_base_href.scheme + "://" + re.sub('[^\\.]+\\.','', parsed_base_href.hostname, count=1)
        www_subdomain_base_url = parsed_base_href.scheme + "://" + "www." + re.sub('[^\\.]+\\.','', parsed_base_href.hostname, count=1)
    
        home_links = []
        links = page_parsed.xpath('//a[@href]')
    
        if links != []:
            for link in links:
                parsed_link = urlparse(link.attrib['href'])
                if parsed_link.query != '' and parsed_link.hostname != None:
                    if parsed_link.path != '':
                        link.attrib['href'] = parsed_link.scheme + "://" + parsed_link.hostname + parsed_link.path
                    else:
                        link.attrib['href'] = parsed_link.scheme + "://" + parsed_link.hostname
                if parsed_link.fragment == '#' and parsed_link.hostname != None:
                    if parsed_link.path != '':
                        link.attrib['href'] = parsed_link.scheme + "://" + parsed_link.hostname + parsed_link.path + "#home"
                    else:
                        link.attrib['href'] = parsed_link.scheme + "://" + parsed_link.hostname +"#home"
    
                if link.attrib['href'] == normal_base_url:
                    home_links.append(link)
                elif link.attrib['href'] == normal_base_url + "/":
                    home_links.append(link)
                elif link.attrib['href'] == www_normal_base_url:
                    home_links.append(link)
                elif link.attrib['href'] == www_normal_base_url + "/":
                    home_links.append(link)
                elif link.attrib['href'] == subdomain_base_url:
                    home_links.append(link)
                elif link.attrib['href'] == subdomain_base_url + "/":
                    home_links.append(link)
                elif link.attrib['href'] == www_subdomain_base_url:
                    home_links.append(link)
                elif link.attrib['href'] == www_subdomain_base_url + "/":
                    home_links.append(link)
    
    
        if home_links == [] and parsed_base_href.scheme == "https":
            normal_base_url = "http://" + parsed_base_href.hostname
            www_normal_base_url = "http://" + "www." + parsed_base_href.hostname
    
            subdomain_base_url = "http://" + re.sub('[^\\.]+\\.','', parsed_base_href.hostname, count=1)
            www_subdomain_base_url = "http://" + "www." + re.sub('[^\\.]+\\.','', parsed_base_href.hostname, count=1)
    
            if links != []:
                for link in links:
                    if link.attrib['href'] == normal_base_url:
                        home_links.append(link)
                    elif link.attrib['href'] == normal_base_url + "/":
                        home_links.append(link)
                    elif link.attrib['href'] == www_normal_base_url:
                        home_links.append(link)
                    elif link.attrib['href'] == www_normal_base_url + "/":
                        home_links.append(link)
                    elif link.attrib['href'] == subdomain_base_url:
                        home_links.append(link)
                    elif link.attrib['href'] == subdomain_base_url + "/":
                        home_links.append(link)
                    elif link.attrib['href'] == www_subdomain_base_url:
                        home_links.append(link)
                    elif link.attrib['href'] == www_subdomain_base_url + "/":
                        home_links.append(link)
    
    
        img_srcs = page_parsed.xpath('//img[@src]')
        inlined_svg = page_parsed.xpath('//svg')
        scripts = page_parsed.xpath('//script')
        icons = []
        icons_inlined = []
        home_link_class_for_css = []
        resources_loaded = []
        svgs_in_home_links = []
        imgs_home_fallback = []
    
        if home_links != []:
            imgs_in_home_links = []
            for home_link in home_links:
                if home_link.xpath('img[@src]') != []:
                    imgs_in_home_links.append(home_link.xpath('img[@src]')[0])
                elif home_link.xpath('svg') != []:
                    svgs_in_home_links.append(home_link.xpath('svg')[0])
            if imgs_in_home_links == []:
                for home_link in home_links:
                    for child_element in home_link.iter():
                        if child_element.xpath('img[@src]') != []:
                            imgs_in_home_links.append(child_element.xpath('img[@src]')[0])
            if svgs_in_home_links == []:
                for home_link in home_links:
                    for child_element in home_link.iter():
                        if child_element.xpath('svg') != []:
                            svgs_in_home_links.append(child_element.xpath('svg')[0])
    
            if imgs_in_home_links != []:
                if len(imgs_in_home_links) == 1:
                    no_of_proposed_logos += 1
    
                    if imgs_in_home_links[0].attrib['src'].startswith("data:image/"):
                        success = await decode_and_write_blob(imgs_in_home_links[0].attrib['src'], input_url)
                        if success is not None:
                            url_parsed = urlparse(input_url)
                            print(input_url + ',' + "./logos/" + url_parsed.hostname + "." + success)
                            return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
                    
                    if unicode_escaped_regex.search(imgs_in_home_links[0].attrib['src']):
                        imgs_in_home_links[0].attrib['src'] = imgs_in_home_links[0].attrib['src'].encode().decode('unicode_escape')
                        
                    if urlencoded_regex.search(imgs_in_home_links[0].attrib['src']):
                        imgs_in_home_links[0].attrib['src'] = unquote(imgs_in_home_links[0].attrib['src'])
    
                    if imgs_in_home_links[0].attrib['src'].startswith("//"):
                        imgs_in_home_links[0].attrib['src'] = "http:" + imgs_in_home_links[0].attrib['src']
    
                    parsed_location = urlparse(imgs_in_home_links[0].attrib['src'])
                    final_location = imgs_in_home_links[0].attrib['src']
                    if parsed_location.netloc == "":
                        imgs_in_home_links[0].attrib['src'] = urljoin(input_url, final_location)
    
                    print(input_url + ',' + imgs_in_home_links[0].attrib['src'])
                    sys.stdout.flush()
                    img_response = ""
    
                    try:
                        if input_url not in background_downloads:
                            background_downloads.add(imgs_in_home_links[0].attrib['src'])
                            img_response = await client.get(url=imgs_in_home_links[0].attrib['src'], headers=headers, follow=True)
                        else:
                            pass
                    except asyncio.TimeoutError:
                        sys.stderr.write("\nPassed Timeout: " + imgs_in_home_links[0].attrib['src'] + "\n")
                        pass
                    except Exception as err:
                        sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + imgs_in_home_links[0].attrib['src'] + "\n")
                        pass
                    background_downloads.discard(imgs_in_home_links[0].attrib['src'])
                    if type(img_response) == aiosonic.HttpResponse:
                        visit = True
                        if "CONTENT-TYPE" in img_response.headers.keys():
                            if "text/html" in img_response.headers['Content-Type']:
                                visit = False
                        if img_response.status_code >= 200 and img_response.status_code < 300 and visit:
                            try:
                                coro_write_img = asyncio.to_thread(writeout_bin_img, await img_response.content(), input_url, imgs_in_home_links[0].attrib['src'], None)
                                await coro_write_img
                            except asyncio.TimeoutError:
                                sys.stderr.write("\nPassed Timeout: " + imgs_in_home_links[0].attrib['src'] + "\n")
                                pass
                            except Exception as err:
                                sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + imgs_in_home_links[0].attrib['src'] + "\n")
                                pass
                
                    return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
                elif len(imgs_in_home_links) > 1:
                    imgs = []
                    for img_link in imgs_in_home_links:
                        for attribute in img_link.attrib:
                            if "logo" in img_link.attrib[attribute].lower():
                                no_of_links += 1
                                imgs.append(img_link.attrib['src'])
                        parent = img_link.getparent()
                        parent_of_parent = img_link.getparent().getparent()
                        grand_grand_parent = img_link.getparent().getparent().getparent()
                        for attribute in parent.attrib:
                            if "logo" in parent.attrib[attribute].lower():
                                no_of_links += 1
                                imgs.append(img_link.attrib['src'])
                        if parent_of_parent is not None:
                            for attribute in parent_of_parent.attrib:
                                if "logo" in parent_of_parent.attrib[attribute].lower():
                                    no_of_links += 1
                                    imgs.append(img_link.attrib['src'])
                        if grand_grand_parent is not None:
                            for attribute in grand_grand_parent.attrib:
                                if "logo" in grand_grand_parent.attrib[attribute].lower():
                                    no_of_links += 1
                                    imgs.append(img_link.attrib['src'])
                        if "logo" in img_link.attrib['src'].lower():
                            no_of_links += 1
                            imgs.append(img_link.attrib['src'])
    
                    for img_link in imgs_in_home_links:
                        for attribute in img_link.attrib:
                            if "icon" in img_link.attrib[attribute].lower():
                                no_of_links += 1
                                icons.append(img_link.attrib['src'])
                        parent = img_link.getparent()
                        parent_of_parent = img_link.getparent().getparent()
                        grand_grand_parent = img_link.getparent().getparent().getparent()
                        for attribute in parent.attrib:
                            if "icon" in parent.attrib[attribute].lower():
                                no_of_links += 1
                                icons.append(img_link.attrib['src'])
                        if parent_of_parent is not None:
                            for attribute in parent_of_parent.attrib:
                                if "icon" in parent_of_parent.attrib[attribute].lower():
                                    no_of_links += 1
                                    icons.append(img_link.attrib['src'])
                        if grand_grand_parent is not None:
                            for attribute in grand_grand_parent.attrib:
                                if "icon" in grand_grand_parent.attrib[attribute].lower():
                                    no_of_links += 1
                                    icons.append(img_link.attrib['src'])
    
                    if len(imgs) > 0:
                        no_of_proposed_logos += 1
    
                        if imgs[0].startswith("data:image/"):
                            success = await decode_and_write_blob(imgs[0], input_url)
                            if success is not None:
                                url_parsed = urlparse(input_url)
                                print(input_url + ',' + "./logos/" + url_parsed.hostname + "." + success)
                                return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
                            return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
                        if unicode_escaped_regex.search(imgs[0]):
                            imgs[0] = imgs[0].encode().decode('unicode_escape')
    
                        if urlencoded_regex.search(imgs[0]):
                            imgs[0] = unquote(imgs[0])
    
                        if imgs[0].startswith("//"):
                            imgs[0] = "http:" + imgs[0]
    
                        if imgs[0].startswith("data:image/"):
                            success = await decode_and_write_blob(imgs[0], input_url)
                            if success is not None:
                                url_parsed = urlparse(input_url)
                                print(input_url + ',' + "./logos/" + url_parsed.hostname + "." + success)
                                return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
                            return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
                        parsed_location = urlparse(imgs[0])
                        final_location = imgs[0]
                        if parsed_location.netloc == "":
                            imgs[0] = urljoin(input_url, final_location)
    
                        img_response = ""
    
                        try:
                            if input_url not in background_downloads:
                                background_downloads.add(imgs[0])
                                img_response = await client.get(url=imgs[0], headers=headers, follow=True)
                            else:
                                pass
                        except asyncio.TimeoutError:
                            sys.stderr.write("\nPassed Timeout: " + imgs[0] + "\n")
                            pass
                        except Exception as err:
                            sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + " for " + imgs[0] + "\n")
                            pass
                        background_downloads.discard(imgs[0])
                        if type(img_response) == aiosonic.HttpResponse:
                            visit = True
                            if "CONTENT-TYPE" in img_response.headers.keys():
                                if "text/html" in img_response.headers['Content-Type']:
                                    visit = False
                            if img_response.status_code >= 200 and img_response.status_code < 300 and visit:
                                try:
                                    coro_write_img = asyncio.to_thread(writeout_bin_img, await img_response.content(), input_url, imgs[0], None)
                                    await coro_write_img
                                except asyncio.TimeoutError:
                                    sys.stderr.write("\nPassed Timeout: " + imgs[0] + "\n")
                                    pass
                                except Exception as err:
                                    sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + " for " + imgs[0] + "\n")
                                    pass
                        print(input_url + ',' + imgs[0])
                        sys.stdout.flush()
                        return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
                    else:
                        for img_link in imgs_in_home_links:
                            no_of_links += 1
                            imgs_home_fallback.append(img_link.attrib['src'])
                        
            elif imgs_in_home_links == []:
                for home_link in home_links:
                    for child in home_link:
                        if "class" in child.attrib.keys():
                            for class_declared in child.attrib['class'].split(" "):
                                home_link_class_for_css.append("." + class_declared)
    
                    if "class" in home_link.attrib.keys():
                        for class_declared in home_link.attrib['class'].split(" "):
                            home_link_class_for_css.append("." + class_declared)
    
                    home_link_parent = home_link.getparent()
                    if home_link_parent is not None:
                        if "class" in home_link_parent.attrib.keys():
                            for class_declared in home_link_parent.attrib['class'].split(" "):
                                home_link_class_for_css.append("." + class_declared)
    
        if len(img_srcs) == 1:
            no_of_proposed_logos += 1
            sys.stdout.flush()
    
            if img_srcs[0].attrib['src'].startswith("data:image/"):
                success = await decode_and_write_blob(img_srcs[0].attrib['src'], input_url)
                if success is not None:
                    url_parsed = urlparse(input_url)
                    print(input_url + ',' + "./logos/" + url_parsed.hostname + "." + success)
                    return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
                return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
            if unicode_escaped_regex.search(img_srcs[0].attrib['src']):
                img_srcs[0].attrib['src'] = img_srcs[0].attrib['src'].encode().decode('unicode_escape')
    
            if urlencoded_regex.search(img_srcs[0].attrib['src']):
                img_srcs[0].attrib['src'] = unquote(img_srcs[0].attrib['src'])
    
            if img_srcs[0].attrib['src'].startswith("//"):
                img_srcs[0].attrib['src'] = "http:" + img_srcs[0].attrib['src']
    
            if img_srcs[0].attrib['src'].startswith("data:image/"):
                success = await decode_and_write_blob(img_srcs[0].attrib['src'], input_url)
                if success is not None:
                    url_parsed = urlparse(input_url)
                    print(input_url + ',' + "./logos/" + url_parsed.hostname + "." + success)
                    return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
                return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
            parsed_location = urlparse(img_srcs[0].attrib['src'])
            final_location = img_srcs[0].attrib['src']
            if parsed_location.netloc == "":
                img_srcs[0].attrib['src'] = urljoin(input_url, final_location)
    
            img_response = ""
    
            try:
                if input_url not in background_downloads:
                    background_downloads.add(img_srcs[0].attrib['src'])
                    img_response = await client.get(url=img_srcs[0].attrib['src'], headers=headers, follow=True)
                else:
                    pass
            except asyncio.TimeoutError:
                sys.stderr.write("\n\naiosonic Passed Timeout: " + img_srcs[0].attrib['src'] + "\n")
                pass
            except Exception as err:
                sys.stderr.write("\n\naiosonic Passed Exception: " + type(err).__name__ + ": " + str(err) + img_srcs[0].attrib['src'] + "\n")
                pass
            background_downloads.discard(img_srcs[0].attrib['src'])
            if type(img_response) == aiosonic.HttpResponse:
                visit = True
                if "CONTENT-TYPE" in img_response.headers.keys():
                    if "text/html" in img_response.headers['Content-Type']:
                        visit = False
                if img_response.status_code >= 200 and img_response.status_code < 300 and visit:
                    try:
                        coro_write_img = asyncio.to_thread(writeout_bin_img, await img_response.content(), input_url, img_srcs[0].attrib['src'], None)
                        await coro_write_img
                    except asyncio.TimeoutError:
                        sys.stderr.write("\nPassed Timeout: " + img_srcs[0].attrib['src'] + "\n")
                        pass
                    except Exception as err:
                        sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + img_srcs[0].attrib['src'] + "\n")
                        pass
            print(input_url + ',' + img_srcs[0].attrib['src'])
            return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
        if len(inlined_svg) > 0:
            svg = ""
            for inlined in inlined_svg:
                parent = inlined.getparent()
                for attribute in parent.attrib.keys():
                    if "icon" in parent.attrib[attribute].lower() or "title" in parent.attrib[attribute].lower():
                        inlined.text = ""
                        for child in inlined.iter():
                            child.text = ""
                        icons_inlined.append(inlined)
            if True:
                for inlined in inlined_svg:
                    for attribute in inlined.attrib.keys():
                        if "icon" in inlined.attrib[attribute].lower() or "title" in inlined.attrib[attribute].lower():
                            inlined.text = ""
                            for child in inlined.iter():
                                child.text = ""
                            icons_inlined.append(inlined)
            if True:
                for inlined in inlined_svg:
                    grandparent = inlined.getparent().getparent()
                    if grandparent is not None:
                        for attribute in grandparent.attrib.keys():
                            if "icon" in grandparent.attrib[attribute].lower() or "title" in grandparent.attrib[attribute].lower():
                                inlined.text = ""
                                for child in inlined.iter():
                                    child.text = ""
                                icons_inlined.append(inlined)
            if True:
                for inlined in inlined_svg:
                    great_grandparent = inlined.getparent().getparent().getparent()
                    if great_grandparent is not None:
                        for attribute in great_grandparent.attrib.keys():
                            if "icon" in great_grandparent.attrib[attribute].lower() or "title" in great_grandparent.attrib[attribute].lower():
                                inlined.text = ""
                                for child in inlined.iter():
                                    child.text = ""
                                icons_inlined.append(inlined)
    
            if svg == "":
                 if len(svgs_in_home_links) > 0:
                     svgs_in_home_links[0].text = ""
                     for child in svgs_in_home_links[0].iter():
                         child.text = ""
                     svg = svgs_in_home_links[0]
            if svg != "":
                for inlined in inlined_svg:
                    for attribute in inlined.attrib.keys():
                        if "logo" in inlined.attrib[attribute].lower():
                            inlined.text = ""
                            for child in inlined.iter():
                                child.text = ""
                            svg = inlined
            if svg != "":
                for inlined in inlined_svg:
                    for attribute in inlined.getparent().attrib.keys():
                        if "logo" in inlined.getparent().attrib[attribute].lower():
                            inlined.text = ""
                            for child in inlined.iter():
                                child.text = ""
                            svg = inlined
            if svg == "":
                for inlined in inlined_svg:
                    for attribute in inlined.getparent().getparent().attrib.keys():
                        if "logo" in inlined.getparent().getparent().attrib[attribute].lower():
                            inlined.text = ""
                            for child in inlined.iter():
                                child.text = ""
                            svg = inlined
            if svg == "":
                for inlined in inlined_svg:
                    great_grandparent = inlined.getparent().getparent().getparent()
                    if great_grandparent is not None:
                        for attribute in great_grandparent.attrib.keys():
                            if "logo" in great_grandparent.attrib[attribute].lower():
                                inlined.text = ""
                                for child in inlined.iter():
                                    child.text = ""
                                svg = inlined
            if svg != "":
                write_thread = asyncio.to_thread(writeout_svg, svg, input_url, False)
                result_write = await write_thread
                if result_write is not None:
                    base_url = urlparse(input_url)
                    print(input_url + ',' + "./logos/" + re.sub('https?:\\/\\/', '', input_url.strip("/"), count=1) + ".svg")
                    no_of_proposed_logos += 1
                    no_of_inlined_svgs += 1
                    sys.stdout.flush()
                    return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
        if True:
            svgs = []
            candidates = []
            logo_list = None
            stylesheets = page_parsed.xpath('//link[contains(@href, ".css")]')
            inline_style = page_parsed.xpath('//style')
    
            found_css = []
            script_css_regex = re.compile('(["\'`])([^"\'`]+)(\\.css)')
            url_regex = re.compile("url\\(([^)]+)\\)")
            escaped_slash_regex = re.compile("\\/")
            for script in scripts:
                if script.text is not None:
                    css_script_finds = script_css_regex.finditer(script.text)
                    if css_script_finds is not None:
                        for css_in_script in css_script_finds:
                            css_in_script_text = css_in_script.group(2) + css_in_script.group(3)
                            if "url(" in css_in_script_text:
                                url_css_match = url_regex.search(css_in_script_text + ")")
                                if url_css_match is not None:
                                    css_in_script_text = url_css_match.group(1)
                            found_css.append(css_in_script_text)
    
            if inline_style != []:
                for style in inline_style:
                    if style.text is not None:
                        logos_proposed_task = asyncio.to_thread(extract_logo_from_css, style.text, input_url, None)
                        logo_list = await logos_proposed_task
                    if logo_list is not None:
                        for logo in logo_list:
                           svgs.append(logo)
    
            if stylesheets != []:
                logo_list = None
                for style_url in set(stylesheets):
                    if style_url.attrib['href'].startswith("data:text/css"):
                        success = await decode_blob(style_url.attrib['href'], input_url)
                        if success is not None:
                            logos_proposed_task = asyncio.to_thread(extract_logo_from_css, success, input_url, None)
                            logo_list = await logos_proposed_task
                            if logo_list is not None:
                                for logo in logo_list:
                                    svgs.append(logo)
                                    continue
                            
                    if unicode_escaped_regex.search(style_url.attrib['href']):
                        style_url.attrib['href'] = style_url.attrib['href'].encode().decode('unicode_escape')
    
                    if urlencoded_regex.search(style_url.attrib['href']):
                        style_url.attrib['href'] = unquote(style_url.attrib['href'])
    
                    if style_url.attrib['href'].startswith("//"):
                        style_url.attrib['href'] = "http:" + style_url.attrib['href']
    
                    parsed_location = urlparse(style_url.attrib['href'])
                    final_location = style_url.attrib['href']
    
                    if parsed_location.netloc == "" and parsed_location.path is not None:
                        final_location = urljoin(input_url, parsed_location.path)
    
                    sheet_download = None
    
                    try:
                        if input_url not in background_downloads:
                            background_downloads.add(final_location)
                            sheet_download = await client.get(url=final_location, headers=headers, follow=True)
                        else:
                            continue
                    except asyncio.TimeoutError:
                        no_of_network_exceptions += 1
                        sys.stderr.write("aiosonic CSS Timeout" + " for " + style_url.attrib['href'] + "\n")
                        sys.stderr.flush()
                        continue
                    except Exception as err:
                        no_of_network_exceptions += 1
                        sys.stderr.write("aiosonic CSS Error:" + " for " + style_url.attrib['href'] + "\n")
                        sys.stderr.flush()
                        continue
                    background_downloads.discard(final_location)
                    if type(sheet_download) is not aiosonic.HttpResponse:
                        no_of_network_exceptions += 1
                        sys.stderr.write("aiosonic CSS Not Response:" +  " for " + style_url.attrib['href'] + "\n")
                        sys.stdout.flush()
                        continue
                    elif sheet_download.status_code >= 200 and sheet_download.status_code < 300:
                        sheet = None
                        sheet_text = None
                        try:
                            sheet_text = await sheet_download.text()
                        except asyncio.TimeoutError:
                            no_of_network_exceptions += 1
                            sys.stderr.write("aiosonic CSS Read Timeout for " + final_location + "\n")
                            sys.stderr.flush()
                            continue
                        except Exception as err:
                            no_of_parsing_exceptions += 1
                            sys.stderr.write("aiosonic CSS Error: " + type(err).__name__ + ": " + str(err) + " for " + final_location + "\n")
                            sys.stderr.flush()
                            continue
                        if sheet_text is None or len(sheet_text) > 2000000 or len(sheet_text) == 0:
                            no_of_too_big_html += 1
                            sys.stderr.flush()
                            continue
                        else:
                           resources_loaded.append(final_location)
                           logos_proposed_task = asyncio.to_thread(extract_logo_from_css, sheet_text, input_url, None)
                           logo_list = await logos_proposed_task
                           if logo_list is not None:
                               for logo in logo_list:
                                   svgs.append(logo)
            if found_css != []:
                logo_list = None
                for css_url in set(found_css):
                        if css_url.startswith("data:text/css"):
                            success = await decode_blob(css_url, input_url)
                            if success is not None:
                                logos_proposed_task = asyncio.to_thread(extract_logo_from_css, success, input_url, None)
                                logo_list = await logos_proposed_task
                                if logo_list is not None:
                                    for logo in logo_list:
                                        svgs.append(logo)
                                        continue
    
                        if unicode_escaped_regex.search(css_url):
                            css_url = css_url.encode().decode('unicode_escape')
    
                        if urlencoded_regex.search(css_url):
                            css_url = unquote(css_url)
    
                        if urlencoded_regex.search(css_url):
                            css_url = unquote(css_url)
    
                        if css_url.startswith("//"):
                            css_url = "http:" + css_url
    
                        sheet_download = None
    
                        parsed_location = urlparse(css_url)
                        final_location = css_url
                        if parsed_location.netloc == "" and parsed_location.path is not None:
                            final_location = urljoin(input_url, parsed_location.path)
    
                        sheet_download = None
    
                        try:
                            if input_url not in background_downloads:
                                background_downloads.add(final_location)
                                sheet_download = await client.get(url=final_location, headers=headers, follow=True)
                            else:
                                continue
                        except asyncio.TimeoutError:
                            no_of_network_exceptions += 1
                            sys.stderr.write("aiosonic CSS Timeout" + " for " + css_url + "\n")
                            sys.stderr.flush()
                            continue
                        except Exception as err:
                            no_of_network_exceptions += 1
                            sys.stderr.write("aiosonic CSS Error: " + type(err).__name__ + ": " + str(err) + " for " + css_url + "\n")
                            sys.stderr.flush()
                            continue
        
                        background_downloads.discard(final_location)
                        if type(sheet_download) is not aiosonic.HttpResponse:
                            no_of_network_exceptions += 1
                            sys.stderr.write("aiosonic CSS Error: " + css_url + "\n")
                            sys.stdout.flush()
                            continue
                        elif sheet_download.status_code >= 200 and sheet_download.status_code < 300:
                            sheet = None
                            sheet_text = None
                            try:
                                sheet_text = await sheet_download.text()
                            except asyncio.TimeoutError:
                                no_of_network_exceptions += 1
                                sys.stderr.write("aiosonic CSS Read Timeout for " + css_url + "\n")
                                sys.stderr.flush()
                                continue
                            except Exception as err:
                                no_of_parsing_exceptions += 1
                                sys.stderr.write("aiosonic CSS Error: " + type(err).__name__ + ": " + str(err) + " for " + css_url + "\n")
                                sys.stderr.flush()
                                continue
                            if sheet_text is None or len(sheet_text) > 2000000 or len(sheet_text) == 0:
                                no_of_too_big_html += 1
                                sys.stderr.flush()
                                continue
                            else:
                               resources_loaded.append(final_location)
                               logos_proposed_task = asyncio.to_thread(extract_logo_from_css, sheet_text, input_url, None)
                               logo_list = await logos_proposed_task
                               if logo_list is not None:
                                   for logo in logo_list:
                                       parsed_logo_url = urlparse(logo[0])
                                       if parsed_logo_url.netloc == "":
                                           logo_url = urljoin(css_url, logo[0])
                                       else:
                                           logo_url = logo[0]
                                       svgs.append([logo[1], logo_url])
            if svgs != []:
                for img in svgs:
                    if "logo" in img[0].lower():
                        candidates.append(img[0])
                        no_of_links += 1
                for img in svgs:
                    if "icon" in img[0].lower() or "title" in img[0].lower():
                        icons.append(img[0])
                        no_of_links += 1
                for img_and_class in svgs:
                    for class_declared in home_link_class_for_css:
                       if class_declared == img_and_class[1]:
                           candidates.append(img_and_class[0])
                           no_of_links += 1
    
                if len(candidates) == 0:
                    for img_and_class in svgs:
                        for class_declared in home_link_class_for_css:
                           if "logo" in class_declared and class_declared == img_and_class[1]:
                               candidates.append(img_and_class[0])
                               no_of_links += 1
    
                if len(candidates) > 0:
                    logo_url = candidates[0]
                    no_of_proposed_logos += 1
                    sys.stdout.flush()
    
                    if candidates[0].startswith("data:image/"):
                        success = await decode_and_write_blob(candidates[0], input_url)
                        if success is not None:
                            url_parsed = urlparse(input_url)
                            print(input_url + ',' + "./logos/" + url_parsed.hostname + "." + success)
                            return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
                        return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
                    if unicode_escaped_regex.search(logo_url):
                        logo_url = logo_url.encode().decode('unicode_escape')
    
                    if urlencoded_regex.search(logo_url):
                        logo_url = unquote(logo_url)
    
                    if logo_url.startswith("//"):
                        logo_url = "http:" + logo_url
    
                    parsed_location = urlparse(logo_url)
                    final_location = logo_url
                    if parsed_location.netloc == "":
                        logo_url = urljoin(input_url, final_location)
    
                    img_response = ""
    
                    try:
                        if input_url not in background_downloads:
                            background_downloads.add(logo_url)
                            img_response = await client.get(url=logo_url, headers=headers, follow=True)
                        else:
                            pass
                    except asyncio.TimeoutError:
                        sys.stderr.write("\nPassed Timeout: " + logo_url + "\n")
                        pass
                    except Exception as err:
                        sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + logo_url + "\n")
                        pass
                    background_downloads.discard(logo_url)
                    if type(img_response) == aiosonic.HttpResponse:
                        visit = True
                        if "CONTENT-TYPE" in img_response.headers.keys():
                            if "text/html" in img_response.headers['Content-Type']:
                                visit = False
                        if img_response.status_code >= 200 and img_response.status_code < 300 and visit:
                            try:
                                coro_write_img = asyncio.to_thread(writeout_bin_img, await img_response.content(), input_url, logo_url, None)
                                await coro_write_img
                            except asyncio.TimeoutError:
                                sys.stderr.write("\nPassed Timeout: " + logo_url + "\n")
                                pass
                            except Exception as err:
                                sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + logo_url + "\n")
                                pass
                    print(input_url + ',' + logo_url)
                    return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
        if len(img_srcs) > 1:
            logos = []
            for img in img_srcs:
                for attribute in img.attrib:
                    if "logo" in img.attrib[attribute].lower():
                        logos.append(img.attrib['src'])
                        no_of_links += 1
                parent = img.getparent()
                parent_of_parent = img.getparent().getparent()
                grand_grand_parent = img.getparent().getparent().getparent()
                for attribute in parent.attrib:
                    if "logo" in parent.attrib[attribute].lower():
                        logos.append(img.attrib['src'])
                        no_of_links += 1
                if parent_of_parent is not None:
                    for attribute in parent_of_parent.attrib:
                        if "logo" in parent_of_parent.attrib[attribute].lower():
                            logos.append(img.attrib['src'])
                            no_of_links += 1
                if grand_grand_parent is not None:
                    for attribute in grand_grand_parent.attrib:
                        if "logo" in grand_grand_parent.attrib[attribute].lower():
                            logos.append(img.attrib['src'])
                            no_of_links += 1
                if "logo" in img.attrib['src'].lower():
                    logos.append(img.attrib['src'])
                    no_of_links += 1
                   
            for img in img_srcs:
                for attribute in img.attrib:
                    if "icon" in img.attrib[attribute].lower() or "title" in img.attrib[attribute].lower():
                        icons.append(img.attrib['src'])
                        no_of_links += 1
                parent = img.getparent()
                parent_of_parent = img.getparent().getparent()
                grand_grand_parent = img.getparent().getparent().getparent()
                for attribute in parent.attrib:
                    if "icon" in parent.attrib[attribute].lower() or "title" in parent.attrib[attribute].lower():
                        icons.append(img.attrib['src'])
                        no_of_links += 1
                if parent_of_parent is not None:
                    for attribute in parent_of_parent.attrib:
                        if "icon" in parent_of_parent.attrib[attribute].lower() or "title" in parent_of_parent.attrib[attribute].lower():
                            icons.append(img.attrib['src'])
                            no_of_links += 1
                if grand_grand_parent is not None:
                    for attribute in grand_grand_parent.attrib:
                        if "icon" in grand_grand_parent.attrib[attribute].lower() or "title" in grand_grand_parent.attrib[attribute].lower():
                            icons.append(img.attrib['src'])
                            no_of_links += 1
    
            if len(logos) > 0:
               no_of_proposed_logos += 1
               if logos[0].startswith("data:image/"):
                   success = await decode_and_write_blob(logos[0], input_url)
                   if success is not None:
                       url_parsed = urlparse(input_url)
                       print(input_url + ',' + "./logos/" + url_parsed.hostname + "." + success)
                       return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
                   return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
               if unicode_escaped_regex.search(logos[0]):
                   logos[0] = logos[0].encode().decode('unicode_escape')
    
               if urlencoded_regex.search(logos[0]):
                   logos[0] = unquote(logos[0])
    
               if logos[0].startswith("//"):
                    logos[0] = "http:" + logos[0]
    
               parsed_location = urlparse(logos[0])
               final_location = logos[0]
               if parsed_location.netloc == "":
                   logos[0] = urljoin(input_url, final_location)
    
               img_response = ""
    
               try:
                   if input_url not in background_downloads:
                       background_downloads.add(logos[0])
                       img_response = await client.get(url=logos[0], headers=headers, follow=True)
                   else:
                       pass
               except asyncio.TimeoutError:
                   sys.stderr.write("\nPassed Timeout: " + logos[0] + "\n")
                   pass
               except Exception as err:
                   sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + " for " + logos[0] + "\n")
                   pass
               background_downloads.discard(logos[0])
    
               if type(img_response) == aiosonic.HttpResponse:
                   visit = True
                   if "CONTENT-TYPE" in img_response.headers.keys():
                       if "text/html" in img_response.headers['Content-Type']:
                            visit = False
                   if img_response.status_code >= 200 and img_response.status_code < 300 and visit:
                       try:
                           coro_write_img = asyncio.to_thread(writeout_bin_img, await img_response.content(), input_url, logos[0], None)
                           await coro_write_img
                       except asyncio.TimeoutError:
                           sys.stderr.write("\nPassed Timeout: " + logos[0] + "\n")
                           pass
                       except Exception as err:
                           sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + " for " + logos[0] + "\n")
                           pass
               print(input_url + ',' + logos[0])
               sys.stdout.flush()
               return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
        if True:
            svgs = []
            candidates = []
            logo_list = None
            inline_scripts = []
            script_list = []
    
            for script in scripts:
                if "src" in script.attrib.keys():
                    script_finds = script.attrib["src"]
                    parsed_script_url = urlparse(script_finds)
                    if parsed_script_url.netloc == "":
                        script_url = urljoin(normal_base_url, script_finds)
                    else:
                        script_url = script_finds
                    script_list.append(script_url)
                if script.text is not None:
                    inline_scripts.append(script.text)
    
            if inline_scripts != []:
                for script in inline_scripts:
                    logos_proposed_task = asyncio.to_thread(extract_logo_from_script, script, input_url, None)
                    logo_list = await logos_proposed_task
                    if logo_list is not None:
                        for logo in logo_list:
                            svgs.append(logo)
    
            if script_list != []:
                for script_url in set(script_list):
                        if script_url.startswith("data:text/javascript"):
                            success = await decode_blob(script_url, input_url)
                            if success is not None:
                                logos_proposed_task = asyncio.to_thread(extract_logo_from_script, success, input_url, None)
                                logo_list = await logos_proposed_task
                                if logo_list is not None:
                                    for logo in logo_list:
                                        svgs.append(logo)
                                        continue
    
                        if unicode_escaped_regex.search(script_url):
                            script_url = script_url.encode().decode('unicode_escape')
    
                        if urlencoded_regex.search(script_url):
                            script_url = unquote(script_url)
    
                        if script_url.startswith("//"):
                           script_url  = "http:" + script_url 
    
                        script_download = None
    
                        parsed_location = urlparse(script_url)
                        final_location = script_url
                        if parsed_location.netloc == "" and parsed_location.path is not None:
                            final_location = urljoin(input_url, parsed_location.path)
    
                        script_download = None
    
                        try:
                           if input_url not in background_downloads:
                               background_downloads.add(final_location)
                               script_download = await client.get(url=final_location, headers=headers, follow=True)
                           else:
                               continue
    
                        except asyncio.TimeoutError:
                            no_of_network_exceptions += 1
                            sys.stderr.write("aiosonic Script Timeout: " + script_url + "\n")
                            sys.stderr.flush()
                            continue
                        except Exception as err:
                            no_of_network_exceptions += 1
                            sys.stderr.write("aiosonic Script Error: " + type(err).__name__ + ": " + str(err) + " for " + script_url + "\n")
                            sys.stderr.flush()
                            continue
                        background_downloads.discard(final_location)
                        if type(script_download) is not aiosonic.HttpResponse:
                            no_of_network_exceptions += 1
                            sys.stderr.write("aiosonic Script Not Response\n")
                            sys.stdout.flush()
                            continue
                        elif script_download.status_code >= 200 and script_download.status_code < 300:
                            script = None
                            script_text = None
                            try:
                                script_text = await script_download.text()
                            except asyncio.TimeoutError:
                                no_of_network_exceptions += 1
                                sys.stderr.write("aiosonic Script Read Timeout for " + final_location + "\n")
                                sys.stderr.flush()
                                continue
                            except Exception as err:
                                no_of_parsing_exceptions += 1
                                sys.stderr.write("aiosonic Script Error: " + type(err).__name__ + ": " + str(err) + " for " + final_location + "\n")
                                sys.stderr.flush()
                                continue
                            if script_text is None or len(script_text) > 2000000 or len(script_text) == 0:
                                no_of_too_big_html += 1
                                sys.stderr.flush()
                                continue
                            else:
                               resources_loaded.append(final_location)
                               logos_proposed_task = asyncio.to_thread(extract_logo_from_script, script_text, input_url, None)
                               logo_list = await logos_proposed_task
                               if logo_list is not None:
                                   for logo in logo_list:
                                       if "url(" in logo:
                                           logos_css_fallback_proposed_task = asyncio.to_thread(extract_logo_from_css, logo, input_url, None)
                                           logo_list_css_fallback = await logos_css_fallback_proposed_task
                                           if logo_list_css_fallback is not None:
                                               for logo_fallback in logo_list_css_fallback:
                                                   svgs.append(logo_fallback[0])
                                       else:
                                           svgs.append(logo)
    
            if svgs != []:
                for img in svgs:
                    if "logo" in img.lower():
                        candidates.append(img)
                        no_of_links += 1
                for img in svgs:
                    if "icon" in img.lower() or "title" in img.lower():
                        icons.append(img)
                        no_of_links += 1
    
                if len(candidates) > 0:
                    logo_url = candidates[0]
                    no_of_proposed_logos += 1
                    sys.stdout.flush()
    
                    if candidates[0].startswith("data:image/"):
                        success = await decode_and_write_blob(candidates[0], input_url)
                        if success is not None:
                            url_parsed = urlparse(input_url)
                            print(input_url + ',' + "./logos/" + url_parsed.hostname + "." + success)
                            return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
                        return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
                    print(input_url + ',' + logo_url)
    
                    if unicode_escaped_regex.search(logo_url):
                        logo_url = logo_url.encode().decode('unicode_escape')
    
                    if urlencoded_regex.search(logo_url):
                        logo_url = unquote(logo_url)
    
                    if logo_url.startswith("//"):
                       logo_url  = "http:" + logo_url 
    
                    parsed_location = urlparse(logo_url)
                    final_location = logo_url
                    if parsed_location.netloc == "":
                       logo_url = urljoin(input_url, final_location)
    
                    img_response = ""
    
                    try:
                        if input_url not in background_downloads:
                             background_downloads.add(logo_url)
                             img_response = await client.get(url=logo_url, headers=headers, follow=True)
                        else:
                            pass
                    except asyncio.TimeoutError:
                        sys.stderr.write("\nPassed Timeout: " + logo_url + "\n")
                        pass
                    except Exception as err:
                        sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + logo_url + "\n")
                        pass
                    background_downloads.discard(logo_url)
                    if type(img_response) == aiosonic.HttpResponse:
                        visit = True
                        if "CONTENT-TYPE" in img_response.headers.keys():
                            if "text/html" in img_response.headers['Content-Type']:
                                visit = False
                        if img_response.status_code >= 200 and img_response.status_code < 300 and visit:
                            try:
                                coro_write_img = asyncio.to_thread(writeout_bin_img, await img_response.content(), input_url, logo_url, None)
                                await coro_write_img
                            except asyncio.TimeoutError:
                                sys.stderr.write("\nPassed Timeout: " + logo_url + "\n")
                                pass
                            except Exception as err:
                                sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + logo_url + "\n")
                                pass
                    return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
                elif len(imgs_home_fallback) > 0:
                    no_of_proposed_logos += 1
                    sys.stdout.flush()
            
                    if unicode_escaped_regex.search(imgs_home_fallback[0]):
                        imgs_home_fallback[0] = imgs_home_fallback[0].encode().decode('unicode_escape')
    
                    if urlencoded_regex.search(imgs_home_fallback[0]):
                        imgs_home_fallback[0] = unquote(imgs_home_fallback[0])
    
                    if imgs_home_fallback[0].startswith("//"):
                        imgs_home_fallback[0] = "http:" + imgs_home_fallback[0]
    
                    if imgs_home_fallback[0].startswith("data:image/"):
                        success = await decode_and_write_blob(imgs_home_fallback[0], input_url)
                        if success != '' :
                            url_parsed = urlparse(input_url)
                            print(input_url + ',' + "./logos/" + url_parsed.hostname + "." + success)
                        return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
                    parsed_location = urlparse(imgs_home_fallback[0])
                    final_location = imgs_home_fallback[0]
                    if parsed_location.netloc == "":
                       imgs_home_fallback[0] = urljoin(input_url, final_location)
    
                    img_response = ""
    
                    try:
                        if input_url not in background_downloads:
                            background_downloads.add(imgs_home_fallback[0])
                            img_response = await client.get(url=imgs_home_fallback[0], headers=headers, follow=True)
                        else:
                            pass
                    except asyncio.TimeoutError:
                        sys.stderr.write("\nPassed Timeout: " + imgs_home_fallback[0] + "\n")
                        pass
                    except Exception as err:
                        sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + " for " + imgs_home_fallback[0] + "\n")
                        pass
                    background_downloads.discard(imgs_home_fallback[0])
                    if type(img_response) == aiosonic.HttpResponse:
                        visit = True
                        if "CONTENT-TYPE" in img_response.headers.keys():
                            if "text/html" in img_response.headers['Content-Type']:
                                visit = False
                        if img_response.status_code >= 200 and img_response.status_code < 300 and visit:
                            try:
                                coro_write_img = asyncio.to_thread(writeout_bin_img, await img_response.content(), input_url, imgs_home_fallback[0], None)
                                await coro_write_img
                            except asyncio.TimeoutError:
                                sys.stderr.write("\nPassed Timeout: " + imgs_home_fallback[0] + "\n")
                                pass
                            except Exception as err:
                                sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + " for " + imgs_home_fallback[0] + "\n")
                                pass
                    print(input_url + ',' + imgs_home_fallback[0])
                    return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
                elif len(icons_inlined) > 0:
                    write_thread = asyncio.to_thread(writeout_svg, icons_inlined[0], input_url, False)
                    result_write = await write_thread
                    if result_write is not None:
                        base_url = urlparse(input_url)
                        print(input_url + ',' + "./logos/" + re.sub('https?:\\/\\/', '', input_url, count=1) + ".svg")
                        no_of_proposed_logos += 1
                        no_of_inlined_svgs += 1
                        sys.stdout.flush()
                        return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
                    elif len(icons) > 0:
                        parsed_logo_url = urlparse(icons[0])
                        base_url = urlparse(input_url)
                        base_url = base_url.scheme + "://" + base_url.netloc
                        if parsed_logo_url.netloc == "":
                            logo_url = urljoin(base_url, icons[0])
                        else:
                            logo_url = icons[0]
                        no_of_proposed_logos += 1
                        sys.stdout.flush()
        
                        if icons[0].startswith("data:image/"):
                            success = await decode_and_write_blob(icons[0], input_url)
                            if success != '' :
                                url_parsed = urlparse(input_url)
                                print(input_url + ',' + "./logos/" + url_parsed.hostname + "." + success)
                            return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
        
                        if unicode_escaped_regex.search(logo_url):
                            logo_url = logo_url.encode().decode('unicode_escape')
    
                        if urlencoded_regex.search(logo_url):
                            logo_url = unquote(logo_url)
    
                        if logo_url.startswith("//"):
                            logo_url = "http:" + logo_url
    
                        parsed_location = urlparse(logo_url)
                        final_location = logo_url
                        if parsed_location.netloc == "":
                           logo_url = urljoin(input_url, final_location)
    
                        img_response = ""
    
                        try:
                            if input_url not in background_downloads:
                                background_downloads.add(logo_url)
                                img_response = await client.get(url=logo_url, headers=headers, follow=True)
                            else:
                                pass
                        except asyncio.TimeoutError:
                            sys.stderr.write("\nPassed Timeout: " + logo_url + "\n")
                            pass
                        except Exception as err:
                            sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + logo_url + "\n")
                            pass
                        background_downloads.discard(logo_url)
                        if type(img_response) == aiosonic.HttpResponse:
                            visit = True
                            if "CONTENT-TYPE" in img_response.headers.keys():
                                if "text/html" in img_response.headers['Content-Type']:
                                    visit = False
                            if img_response.status_code >= 200 and img_response.status_code < 300 and visit:
                                try:
                                    coro_write_img = asyncio.to_thread(writeout_bin_img, await img_response.content(), input_url, logo_url, None)
                                    await coro_write_img
                                except asyncio.TimeoutError:
                                    sys.stderr.write("\nPassed Timeout: " + logo_url + "\n")
                                    pass
                                except Exception as err:
                                    sys.stderr.write("\nPassed Exception: " + type(err).__name__ + ": " + str(err) + logo_url + "\n")
                                    pass
                        print(input_url + ',' + logo_url)
                        return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
        if True:
            svgs = []
            candidates = []
            logo_list = None
            inline_scripts = []
            script_list = []
    
            for script in scripts:
                if script.text is not None:
                    inline_scripts.append(script.text)
    
            if inline_scripts != []:
                for script in inline_scripts:
                    script_refresh_regex = re.compile('location.href *= *["\'`]([^"\'`]+)["\'`]')
                    script_refresh = script_refresh_regex.search(script)
                    if script_refresh is not None:
                        parsed_location = urlparse(script_refresh.group(1))
                        final_location = script_refresh.group(1)
    
                        if unicode_escaped_regex.search(final_location):
                            final_location = final_location.encode().decode('unicode_escape')
    
                        if urlencoded_regex.search(final_location):
                            final_location = unquote(final_location)
    
                        if final_location.startswith("//"):
                           final_location = "http:" + final_location
    
                        if parsed_location.netloc == "" :
                            final_location = urljoin(input_url, final_location)
                        cookies = None
                        if "cookies" in headers.keys():
                            cookies = headers['cookies']
                        return await download_and_deduce(client, final_location, refreshed + 1, cookies)
    
        sys.stderr.write(input_url + ' | ' + "Heuristics Failed")
        """if len(resources_loaded) > 0:
            sys.stderr.write(" | Resources Loaded:\n")
            for res in resources_loaded:
                sys.stderr.write("    " + res + "\n")"""
        sys.stderr.write("\n")
        no_of_heuristic_fails += 1
        sys.stdout.flush()
        return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    
    except Exception as err:
        sys.stderr.write("General Error: " + type(err).__name__ + ": " + str(err) + " for " + input_url + "\n")
        no_of_general_errors += 1
        return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]
    except asyncio.CancelledError as err:
        sys.stderr.write("Task Cancelled: " + type(err).__name__ + ": " + str(err) + " for " + input_url + "\n")
        no_of_general_errors += 1
        return [0, no_of_network_exceptions, no_of_parsing_exceptions, no_of_heuristic_fails, no_of_too_big_html, no_of_http_errors, no_of_proposed_logos, no_of_inlined_svgs]

async def main():
    background_tasks = set()
    max_clients = 300
    
    connector = aiosonic.connectors.TCPConnector(pool_size=max_clients, pool_cls=aiosonic.pools.CyclicQueuePool, timeouts=aiosonic.timeout.Timeouts(sock_connect=20, sock_read=20, pool_acquire=10, request_timeout=180), resolver=aiosonic.resolver.AsyncResolver(nameservers=["8.8.8.8", "1.1.1.1", "9.9.9.9", "4.2.2.1", "208.67.222.222", "64.6.64.6", "74.82.42.42", "8.26.56.26", "185.121.177.177", "37.235.1.174", "80.80.80.80", "216.131.65.63", "91.239.100.100", "119.29.29.29"]))
    client = aiosonic.HTTPClient(connector=connector, handle_cookies=False, verify_ssl=False)
    done_reading = False

    while True:
        if len(background_tasks) < max_clients:
            for _ in range(0, max_clients - len(background_tasks)):
                input = sys.stdin.readline()
                if input != "":
                    task = asyncio.create_task(download_and_deduce(client, "http://" + input.rstrip("\n"), 0, None))
                    background_tasks.add(task)
                    task.add_done_callback(sum_partial_stats)
                    task.add_done_callback(background_tasks.discard)
                else:
                    done_reading = True
                    break
        else:
            await asyncio.sleep(0.02)
        if done_reading is True:
            break
    while len(asyncio.all_tasks()) > 1:
        await asyncio.sleep(0.02)
    del background_tasks

if __name__ == "__main__":
    list_of_stats = [0, 0, 0, 0, 0, 0, 0, 0]
    no_of_tried_urls = 0
    background_downloads = set()

    asyncio.run(main())
    final_stats = list_of_stats
    no_of_network_exceptions = final_stats[1]
    no_of_parsing_exceptions = final_stats[2]
    no_of_heuristic_fails = final_stats[3]
    no_of_too_big_html = final_stats[4]
    no_of_http_errors = final_stats[5]
    no_of_proposed_logos = final_stats[6]
    no_of_inlined_svgs = final_stats[7]

    sys.stderr.write("\nStatistics for this run: \n")
    sys.stderr.write(str(no_of_tried_urls) + " URLs visitation attempts\n")
    sys.stderr.write(str(no_of_network_exceptions) + " Network Exceptions occurred\n")
    sys.stderr.write(str(no_of_parsing_exceptions) + " Parsing Exceptions occurred\n")
    sys.stderr.write(str(no_of_heuristic_fails) + " Failed Heuristic Detections\n")
    sys.stderr.write(str(no_of_too_big_html) + " Too Big or 0-bytes HTMLs\n")
    sys.stderr.write(str(no_of_http_errors) + " Total HTTP(S) errors\n")
    sys.stderr.write(str(no_of_proposed_logos) + " Proposed Logos\n")
    sys.stderr.write(str(no_of_inlined_svgs) + " Inlined SVGs\n\n")
