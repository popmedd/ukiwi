from core.base_loader import base_loader
from core.parse import parsing_pcap
from multiprocessing import Pool
import os
def static_analysis(pcap_name):
    pool = Pool(processes=10)
    pcap_detil = parsing_pcap(pcap_name)
    for parent, dirnames, filenames in os.walk('./plugins',  followlinks=True):
        for filename in filenames:
            file_path = os.path.join(parent, filename)
            pool.apply(base_loader, args=(pcap_detil,file_path))
    pool.close()
    pool.join()