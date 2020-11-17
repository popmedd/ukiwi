#!/usr/bin/python
# -*- coding: UTF-8 -*-
import sys
import dpkt
import socket
import gzip

def parsing_pcap(file_name):
    result = {}
    result['file_name'] = file_name
    result['detils'] = {}
    pcap_file = open(file_name, 'rb')
    pcap_detil = dpkt.pcap.Reader(pcap_file)
    flow_id = 0
    for time, buf in pcap_detil:
        flow_detil = {}
        flow_id +=1
        flow_detil['timestamp'] = time
        flow_detil['flow_id'] = flow_id
        flow_detil['buf_length'] = len(buf)
        eth = dpkt.ethernet.Ethernet(buf)
        try:
            addressing_mode = eth.data.__class__.__name__
            flow_detil['addressing_mode'] = addressing_mode
            if addressing_mode == "IP":
                ip = eth.data
                flow_detil['src_ip'] = socket.inet_ntop(socket.AF_INET, ip.src)
                flow_detil['dst_ip'] = socket.inet_ntop(socket.AF_INET, ip.dst)
                flow_protocol = ip.data.__class__.__name__
                if flow_protocol == "TCP":
                    tcp = ip.data
                    flow_detil['src_port'] = str(tcp.sport)
                    flow_detil['dst_port'] = str(tcp.dport)
                    tcp_data = tcp.data.decode("utf8", "ignore")
                    # 原始数据
                    # print(repr(http_detil))
                    try:
                        http_detil = dpkt.http.Request(tcp.data)
                        flow_detil['flow_protocol'] = 'HTTP'
                        flow_detil['http_request'] = {}
                        flow_detil['tcp_data'] = tcp_data
                        flow_detil['tcp_raw_data'] = tcp.data.hex()
                        for http_type in dir(http_detil):
                            if all(_ not in http_type for _ in ["pack", "pack_hdr", "_"]):
                                http_data = getattr(http_detil, http_type)
                                if isinstance(http_data,bytes):
                                    http_data = http_data.decode('UTF-8', 'ignore')
                                if len(http_data) >0:
                                    flow_detil['http_request'][http_type] = http_data
                                if "headers" not in flow_detil['http_request'].keys():
                                    flow_detil['http_request']['headers'] = None
                    except:
                        try:
                            http_detil = dpkt.http.Response(tcp.data)
                            flow_detil['flow_protocol'] = 'HTTP'
                            flow_detil['http_response'] = {}
                            flow_detil['tcp_data'] = tcp_data
                            flow_detil['tcp_raw_data'] = tcp.data.hex()
                            for http_type in dir(http_detil):
                                if all(_ not in http_type for _ in ["pack", "pack_hdr", "_"]):
                                    http_data = getattr(http_detil, http_type)
                                    if isinstance(http_data,bytes):
                                        http_data = http_data.decode('UTF-8', 'ignore')
                                    if len(http_data) >0:    
                                        flow_detil['http_response'][http_type] = http_data
                                    else:
                                        flow_detil['http_response'][http_type] = "None"
                        except:
                            tcp_data = tcp.data
                            flow_detil['flow_protocol'] = 'TCP'
                            if isinstance(tcp_data,bytes):
                                tcp_data= tcp_data.decode('UTF-8', 'ignore')
                            if len(tcp.data) > 0:
                                flow_detil['tcp_data'] = tcp_data
                                flow_detil['tcp_raw_data'] = tcp.data.hex()
                            else:   
                                flow_detil['tcp_data'] = "None"
                    # 合并流
                    src_ip = flow_detil['src_ip']
                    dst_ip = flow_detil['dst_ip']
                    src_port = flow_detil['src_port']
                    dst_port = flow_detil['dst_port']
                    flow_name_1 = "{}_{}_{}_{}".format(src_ip,src_port,dst_ip,dst_port)
                    flow_name_2 = "{}_{}_{}_{}".format(dst_ip,dst_port,src_ip,src_port)
                    if flow_name_1 in result['detils']:
                        result['detils'][flow_name_1].append(flow_detil)
                    elif flow_name_2 in result['detils']:
                        result['detils'][flow_name_2].append(flow_detil)
                    else:
                        result['detils'][flow_name_1] = []
        except Exception as e:
            print(e)
    pcap_file.close()
    for flow_detil in list(result['detils'].keys()):
        if len(result['detils'][flow_detil]) ==0 :
            del result['detils'][flow_detil]
    return result

