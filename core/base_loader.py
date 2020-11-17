import yaml
import re
from yaml import Loader, Dumper
from core.decode import decode
import time


def check_status(result_dict):
    for key in result_dict.keys():
        status_list = result_dict[key]
        if len(status_list) == 0:
            return False
        elif all("not check" not in _ for _ in status_list):
            return True


def base_loader(pcap_detil, yaml_filename):
    yaml_file = open(yaml_filename, 'r')
    data = yaml.load(yaml_file, Loader=yaml.FullLoader)
    for flow in pcap_detil['detils']:
        check_result = {}
        check_result['yaml_file'] = yaml_filename
        check_result['description'] = data['info']['description']
        check_result['flow_detil'] = []
        check_result['status'] = {}
        check_result['status']['http'] = []
        check_result['status']['tcp'] = []
        tcp_all_data = ''
        for flow_detil in pcap_detil['detils'][flow]:
            flow_protocol = flow_detil['flow_protocol'].lower()
            if flow_protocol == "http":
                if len(flow_detil['tcp_data']) > 0:
                    tcp_all_data += flow_detil['tcp_data'].strip("\r\n")
                if "http_req" in data['match'].keys() and 'http_request' in flow_detil.keys():
                    if data['match']['http_req']['method'].upper() == flow_detil['http_request']['method']:
                        if 'uri' in data['match']['http_req'].keys():
                            uri = flow_detil['http_request']['uri']
                            for stigma in data['match']['http_req']['uri'].keys():
                                if "content" in stigma and str(data['match']['http_req']['uri'][stigma]) in uri:
                                    check_result['status']['http'].append(
                                        "http uri {} checked".format(stigma))
                                elif "decode" in stigma:
                                    uri = decode(
                                        uri, data['match']['http_req']['uri'][stigma])
                                elif "re" in stigma and re.search(data['match']['http_req']['uri'][stigma], uri) != None:
                                    check_result['status']['http'].append(
                                        "http uri re {} checked".format(stigma))
                                else:
                                    check_result['status']['http'].append(
                                        "http req {} not checked".format(stigma))
                        if "headers" in data['match']['http_req'].keys() and flow_detil['http_request']['headers'] != None:
                            for stigma in data['match']['http_req']['headers'].keys():
                                if stigma in flow_detil['http_request']['headers'].keys():
                                    header_data = flow_detil['http_request']['headers'][stigma]
                                    for key in data['match']['http_req']['headers'][stigma].keys():
                                        if "content" in key and data['match']['http_req']['headers'][stigma][key] in header_data:
                                            check_result['status']['http'].append(
                                                "http req headers {} {} checked".format(stigma, key))
                                        elif "decode" in key:
                                            header_data = decode(
                                                header_data, data['match']['http_req']['headers'][stigma][key])
                                        elif "re" in key and re.search(data['match']['http_req']['uri'][stigma][key], header_data) != None:
                                            check_result['status']['http'].append(
                                                "http headers {} {} checked".format(stigma, key))
                                        else:
                                            check_result['status']['http'].append(
                                                "http req headers {} not checked".format(stigma))
                                else:
                                    check_result['status']['http'].append(
                                        "headers {} not checked".format(stigma))
                        if "body" in data['match']['http_req'].keys() and flow_detil['http_request']['body'] != None:
                            body_data = flow_detil['http_request']['body']
                            for stigma in data['match']['http_req']['body'].keys():
                                if "content" in stigma and data['match']['http_req']['body'][stigma] in body_data:
                                    check_result['status']['http'].append(
                                        "http req body {} checked".format(stigma))
                                elif "decode" in stigma:
                                    body_data = decode(
                                        body_data, data['match']['http_req']['body'][stigma])
                                elif "re" in stigma and re.search(data['match']['http_req']['body'][stigma], uri) != None:
                                    check_result['status']['http'].append(
                                        "http body re {} checked".format(stigma))
                                else:
                                    check_result['status']['http'].append(
                                        "http req {} not checked".format(stigma))
                    else:
                        check_result['status']['http'].append(
                            "http method {} not checked".format('method'))
                if "http_resp" in data['match'].keys() and 'http_response' in flow_detil.keys():
                    for stigma in data['match']['http_resp'].keys():
                        if "status" in stigma:
                            if str(data['match']['http_resp']['status']) == str(flow_detil['http_response']['status']):
                                check_result['status']['http'].append(
                                    "http resp status {} checked".format("status"))
                        elif "body" in stigma:
                            http_resp_body = flow_detil['http_response']['body']
                            for key in data['match']['http_resp']['body'].keys():
                                if "content" in key and data['match']['http_resp']['body'][key] in http_resp_body:
                                    check_result['status']['http'].append("http resp body {} checked".format(key))
                                elif "decode" in key:
                                    decode(http_resp_body,data['match']['http_resp']['body'][key])
                                elif "re" in key and re.search(data['match']['http_resp']['body'][key], http_resp_body) != None:
                                    check_result['status']['http'].append("http resp body {} checked".format(key))
                                else:
                                    check_result['status']['http'].append("http resp body {} not checked".format(key))
                        else:
                            check_result['status']['http'].append(
                                "http resp {} not checked".format("status"))
            if flow_protocol == "tcp":
                if len(flow_detil['tcp_data']) > 0:
                    tcp_all_data += flow_detil['tcp_data'].strip("\r\n")
            if check_status(check_result['status']):
                check_result['flow_detil'].append(flow_detil)
        if len(tcp_all_data) > 0:
            if "http_req" in data['match'].keys():
                if data['match']['http_req']['method'].upper() in tcp_all_data:
                    for key in data['match']['http_req'].keys():
                        if "uri" in key:
                            uri = tcp_all_data
                            for stigma in data['match']['http_req']['uri'].keys():
                                if "content" in stigma and data['match']['http_req']['uri'][stigma] in uri:
                                    check_result['status']['tcp'].append(
                                        "tcp uri {} checked".format(stigma))
                                elif "decode" in stigma:
                                    uri = decode(
                                        uri, data['match']['http_req']['uri'][stigma])
                                elif "re" in stigma and re.search(data['match']['http_req']['uri'][stigma], uri) != None:
                                    check_result['status']['tcp'].append(
                                        "tcp uri re {} checked".format(stigma))
                                else:
                                    check_result['status']['tcp'].append(
                                        "tcp uri {} not checked".format(stigma))
                        if "headers" in key:
                            header_data = tcp_all_data
                            for stigma in data['match']['http_req']['headers'].keys():
                                if stigma.lower() in tcp_all_data.lower():
                                    for key in data['match']['http_req']['headers'][stigma].keys():
                                        if "content" in key and data['match']['http_req']['headers'][stigma][key] in header_data:
                                            check_result['status']['tcp'].append(
                                                "tcp req headers {} checked".format(key))
                                        elif "decode" in key:
                                            header_data = decode(
                                                header_data, data['match']['http_req']['headers'][stigma][key])
                                        elif "re" in key and re.search(data['match']['http_req']['headers'][stigma][key], header_data) != None:
                                            check_result['status']['tcp'].append(
                                                "tcp req headers {} checked".format(key))
                                        else:
                                            check_result['status']['tcp'].append(
                                                "tcp req headers {} not checked".format(key))
                                else:
                                    check_result['status']['tcp'].append(
                                        "tcp req headers {} not checked".format(key))
                        if "body" in key:
                            body_data = tcp_all_data
                            for stigma in data['match']['http_req']['body'].keys():
                                if "content" in stigma and data['match']['http_req']['body'][stigma] in body_data:
                                    check_result['status']['tcp'].append(
                                        "http req body {} checked".format(stigma))
                                elif "decode" in stigma:
                                    body_data = decode(
                                        body_data, data['match']['http_req']['body'][stigma])
                                elif "re" in stigma and re.search(data['match']['http_req']['body'][stigma], uri) != None:
                                    check_result['status']['tcp'].append(
                                        "http body re {} checked".format(stigma))
                                else:
                                    check_result['status']['tcp'].append(
                                        "http req {} not checked".format(stigma))
                else:
                    check_result['status']['tcp'].append(
                        "tcp req {} not checked".format('method'))
            if "http_resp" in data['match'].keys():
                http_resp_data = tcp_all_data
                for stigma in data['match']['http_resp'].keys():
                    if "status" in stigma:
                        if str(data['match']['http_resp']['status']) in http_resp_data:
                            check_result['status']['tcp'].append(
                                "http resp status {} checked".format("status"))
                    elif "body" in stigma:
                        for key in data['match']['http_resp']['body'].keys():
                            if "content" in key and data['match']['http_resp']['body'][key] in http_resp_data:
                                check_result['status']['tcp'].append(
                                    "http resp body {} checked".format("status"))
                            elif "decode" in key:
                                http_resp_data = decode(
                                    http_resp_data, data['match']['http_resp']['body'][key])
                            elif "re" in key and re.search(data['match']['http_resp']['body'][key], http_resp_data) != None:
                                check_result['status']['tcp'].append(
                                    "http resp body {} checked".format("status"))
                    else:
                        check_result['status']['tcp'].append(
                            "http resp {} not checked".format("status"))
        if len(check_result['status']['http']) == 0 and len(check_result['status']['tcp']) == 0:
            check_result['status']['http'].append("not checked")
            check_result['status']['tcp'].append("not checked")
        if check_status(check_result['status']):
            print(check_result['description'])
            print(check_result['status'])
            # print(tcp_all_data)
