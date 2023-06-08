from tqdm import tqdm
import os
import pandas

dict_7classes = {'DDoS-RSTFINFlood': 'DDoS', 'DDoS-PSHACK_Flood': 'DDoS', 'DDoS-SYN_Flood': 'DDoS',
                      'DDoS-UDP_Flood': 'DDoS', 'DDoS-TCP_Flood': 'DDoS', 'DDoS-ICMP_Flood': 'DDoS',
                      'DDoS-SynonymousIP_Flood': 'DDoS', 'DDoS-ACK_Fragmentation': 'DDoS',
                      'DDoS-UDP_Fragmentation': 'DDoS',
                      'DDoS-ICMP_Fragmentation': 'DDoS', 'DDoS-SlowLoris': 'DDoS', 'DDoS-HTTP_Flood': 'DDoS',
                      'DoS-UDP_Flood': 'DoS', 'DoS-SYN_Flood': 'DoS', 'DoS-TCP_Flood': 'DoS',
                      'DoS-HTTP_Flood': 'DoS',
                      'Mirai-greeth_flood': 'Mirai', 'Mirai-greip_flood': 'Mirai', 'Mirai-udpplain': 'Mirai',
                      'Recon-PingSweep': 'Recon', 'Recon-OSScan': 'Recon', 'Recon-PortScan': 'Recon',
                      'VulnerabilityScan': 'Recon', 'Recon-HostDiscovery': 'Recon', 'DNS_Spoofing': 'Spoofing',
                      'MITM-ArpSpoofing': 'Spoofing', 'BenignTraffic': 'Benign', 'BrowserHijacking': 'Web',
                      'Backdoor_Malware': 'Web', 'XSS': 'Web', 'Uploading_Attack': 'Web', 'SqlInjection': 'Web',
                      'CommandInjection': 'Web', 'DictionaryBruteForce': 'BruteForce'}


def main():
    path = os.path.dirname(os.path.realpath(__file__)) # заменить
    df_sets = [k for k in os.listdir(path) if k.endswith('.csv')]
    calc_dct = {}
    for file in tqdm(df_sets):
        label_df = pandas.read_csv(file, usecols=['label'])
        arr = label_df['label'].to_numpy()
        for attack in arr:
            attack_type = dict_7classes[attack]
            if not calc_dct.get(attack_type):
                calc_dct[attack_type] = 1
            else:
                calc_dct[attack_type] += 1
    print(calc_dct)


if __name__ == '__main__':
    main()
