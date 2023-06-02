# Training a ML model using CICIoT2023

import pandas as pd
import numpy as np
import os
from tqdm import tqdm
import warnings
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, confusion_matrix


class IOT:

    def __init__(self):
        warnings.filterwarnings('ignore')
        self.DATASET_DIRECTORY = 'C:\\CICIoT2023\\'

        self.dict_2classes = {'DDoS-RSTFINFlood': 'Attack', 'DDoS-PSHACK_Flood': 'Attack', 'DDoS-SYN_Flood': 'Attack',
                              'DDoS-UDP_Flood': 'Attack', 'DDoS-TCP_Flood': 'Attack', 'DDoS-ICMP_Flood': 'Attack',
                              'DDoS-SynonymousIP_Flood': 'Attack', 'DDoS-ACK_Fragmentation': 'Attack',
                              'DDoS-UDP_Fragmentation': 'Attack', 'DDoS-ICMP_Fragmentation': 'Attack',
                              'DDoS-SlowLoris': 'Attack',
                              'DDoS-HTTP_Flood': 'Attack', 'DoS-UDP_Flood': 'Attack', 'DoS-SYN_Flood': 'Attack',
                              'DoS-TCP_Flood': 'Attack', 'DoS-HTTP_Flood': 'Attack', 'Mirai-greeth_flood': 'Attack',
                              'Mirai-greip_flood': 'Attack', 'Mirai-udpplain': 'Attack', 'Recon-PingSweep': 'Attack',
                              'Recon-OSScan': 'Attack', 'Recon-PortScan': 'Attack', 'VulnerabilityScan': 'Attack',
                              'Recon-HostDiscovery': 'Attack', 'DNS_Spoofing': 'Attack', 'MITM-ArpSpoofing': 'Attack',
                              'BrowserHijacking': 'Attack', 'Backdoor_Malware': 'Attack', 'XSS': 'Attack',
                              'Uploading_Attack': 'Attack', 'SqlInjection': 'Attack', 'CommandInjection': 'Attack',
                              'DictionaryBruteForce': 'Attack', 'BenignTraffic': 'Benign'}

        self.DDoS = {'DDoS-RSTFINFlood': 'Attack', 'DDoS-PSHACK_Flood': 'Attack', 'DDoS-SYN_Flood': 'Attack',
                     'DDoS-UDP_Flood': 'Attack', 'DDoS-TCP_Flood': 'Attack', 'DDoS-ICMP_Flood': 'Attack',
                     'DDoS-SynonymousIP_Flood': 'Attack', 'DDoS-ACK_Fragmentation': 'Attack',
                     'DDoS-UDP_Fragmentation': 'Attack', 'DDoS-ICMP_Fragmentation': 'Attack',
                     'DDoS-SlowLoris': 'Attack',
                     'DDoS-HTTP_Flood': 'Attack', 'DoS-UDP_Flood': 'Benign', 'DoS-SYN_Flood': 'Benign',
                     'DoS-TCP_Flood': 'Benign', 'DoS-HTTP_Flood': 'Benign', 'Mirai-greeth_flood': 'Benign',
                     'Mirai-greip_flood': 'Benign', 'Mirai-udpplain': 'Benign', 'Recon-PingSweep': 'Benign',
                     'Recon-OSScan': 'Benign', 'Recon-PortScan': 'Benign', 'VulnerabilityScan': 'Benign',
                     'Recon-HostDiscovery': 'Benign', 'DNS_Spoofing': 'Benign', 'MITM-ArpSpoofing': 'Benign',
                     'BrowserHijacking': 'Benign', 'Backdoor_Malware': 'Benign', 'XSS': 'Benign',
                     'Uploading_Attack': 'Benign', 'SqlInjection': 'Benign', 'CommandInjection': 'Benign',
                     'DictionaryBruteForce': 'Benign', 'BenignTraffic': 'Benign'}

        self.DoS = {'DDoS-RSTFINFlood': 'Benign', 'DDoS-PSHACK_Flood': 'Benign', 'DDoS-SYN_Flood': 'Benign',
                    'DDoS-UDP_Flood': 'Benign', 'DDoS-TCP_Flood': 'Benign', 'DDoS-ICMP_Flood': 'Benign',
                    'DDoS-SynonymousIP_Flood': 'Benign', 'DDoS-ACK_Fragmentation': 'Benign',
                    'DDoS-UDP_Fragmentation': 'Benign', 'DDoS-ICMP_Fragmentation': 'Benign', 'DDoS-SlowLoris': 'Benign',
                    'DDoS-HTTP_Flood': 'Benign', 'DoS-UDP_Flood': 'Attack', 'DoS-SYN_Flood': 'Attack',
                    'DoS-TCP_Flood': 'Attack', 'DoS-HTTP_Flood': 'Attack', 'Mirai-greeth_flood': 'Benign',
                    'Mirai-greip_flood': 'Benign', 'Mirai-udpplain': 'Benign', 'Recon-PingSweep': 'Benign',
                    'Recon-OSScan': 'Benign', 'Recon-PortScan': 'Benign', 'VulnerabilityScan': 'Benign',
                    'Recon-HostDiscovery': 'Benign', 'DNS_Spoofing': 'Benign', 'MITM-ArpSpoofing': 'Benign',
                    'BrowserHijacking': 'Benign', 'Backdoor_Malware': 'Benign', 'XSS': 'Benign',
                    'Uploading_Attack': 'Benign', 'SqlInjection': 'Benign', 'CommandInjection': 'Benign',
                    'DictionaryBruteForce': 'Benign', 'BenignTraffic': 'Benign'}

        self.Mirai = {'DDoS-RSTFINFlood': 'Benign', 'DDoS-PSHACK_Flood': 'Benign', 'DDoS-SYN_Flood': 'Benign',
                      'DDoS-UDP_Flood': 'Benign', 'DDoS-TCP_Flood': 'Benign', 'DDoS-ICMP_Flood': 'Benign',
                      'DDoS-SynonymousIP_Flood': 'Benign', 'DDoS-ACK_Fragmentation': 'Benign',
                      'DDoS-UDP_Fragmentation': 'Benign', 'DDoS-ICMP_Fragmentation': 'Benign',
                      'DDoS-SlowLoris': 'Benign',
                      'DDoS-HTTP_Flood': 'Benign', 'DoS-UDP_Flood': 'Benign', 'DoS-SYN_Flood': 'Benign',
                      'DoS-TCP_Flood': 'Benign', 'DoS-HTTP_Flood': 'Benign', 'Mirai-greeth_flood': 'Attack',
                      'Mirai-greip_flood': 'Attack', 'Mirai-udpplain': 'Attack', 'Recon-PingSweep': 'Benign',
                      'Recon-OSScan': 'Benign', 'Recon-PortScan': 'Benign', 'VulnerabilityScan': 'Benign',
                      'Recon-HostDiscovery': 'Benign', 'DNS_Spoofing': 'Benign', 'MITM-ArpSpoofing': 'Benign',
                      'BrowserHijacking': 'Benign', 'Backdoor_Malware': 'Benign', 'XSS': 'Benign',
                      'Uploading_Attack': 'Benign', 'SqlInjection': 'Benign', 'CommandInjection': 'Benign',
                      'DictionaryBruteForce': 'Benign', 'BenignTraffic': 'Benign'}

        self.Recon = {'DDoS-RSTFINFlood': 'Benign', 'DDoS-PSHACK_Flood': 'Benign', 'DDoS-SYN_Flood': 'Benign',
                      'DDoS-UDP_Flood': 'Benign', 'DDoS-TCP_Flood': 'Benign', 'DDoS-ICMP_Flood': 'Benign',
                      'DDoS-SynonymousIP_Flood': 'Benign', 'DDoS-ACK_Fragmentation': 'Benign',
                      'DDoS-UDP_Fragmentation': 'Benign', 'DDoS-ICMP_Fragmentation': 'Benign',
                      'DDoS-SlowLoris': 'Benign',
                      'DDoS-HTTP_Flood': 'Benign', 'DoS-UDP_Flood': 'Benign', 'DoS-SYN_Flood': 'Benign',
                      'DoS-TCP_Flood': 'Benign', 'DoS-HTTP_Flood': 'Benign', 'Mirai-greeth_flood': 'Benign',
                      'Mirai-greip_flood': 'Benign', 'Mirai-udpplain': 'Benign', 'Recon-PingSweep': 'Attack',
                      'Recon-OSScan': 'Attack', 'Recon-PortScan': 'Attack', 'VulnerabilityScan': 'Attack',
                      'Recon-HostDiscovery': 'Attack', 'DNS_Spoofing': 'Benign', 'MITM-ArpSpoofing': 'Benign',
                      'BrowserHijacking': 'Benign', 'Backdoor_Malware': 'Benign', 'XSS': 'Benign',
                      'Uploading_Attack': 'Benign', 'SqlInjection': 'Benign', 'CommandInjection': 'Benign',
                      'DictionaryBruteForce': 'Benign', 'BenignTraffic': 'Benign'}

        self.Spoofing = {'DDoS-RSTFINFlood': 'Benign', 'DDoS-PSHACK_Flood': 'Benign', 'DDoS-SYN_Flood': 'Benign',
                         'DDoS-UDP_Flood': 'Benign', 'DDoS-TCP_Flood': 'Benign', 'DDoS-ICMP_Flood': 'Benign',
                         'DDoS-SynonymousIP_Flood': 'Benign', 'DDoS-ACK_Fragmentation': 'Benign',
                         'DDoS-UDP_Fragmentation': 'Benign', 'DDoS-ICMP_Fragmentation': 'Benign',
                         'DDoS-SlowLoris': 'Benign',
                         'DDoS-HTTP_Flood': 'Benign', 'DoS-UDP_Flood': 'Benign', 'DoS-SYN_Flood': 'Benign',
                         'DoS-TCP_Flood': 'Benign', 'DoS-HTTP_Flood': 'Benign', 'Mirai-greeth_flood': 'Benign',
                         'Mirai-greip_flood': 'Benign', 'Mirai-udpplain': 'Benign', 'Recon-PingSweep': 'Benign',
                         'Recon-OSScan': 'Benign', 'Recon-PortScan': 'Benign', 'VulnerabilityScan': 'Benign',
                         'Recon-HostDiscovery': 'Benign', 'DNS_Spoofing': 'Attack', 'MITM-ArpSpoofing': 'Attack',
                         'BrowserHijacking': 'Benign', 'Backdoor_Malware': 'Benign', 'XSS': 'Benign',
                         'Uploading_Attack': 'Benign', 'SqlInjection': 'Benign', 'CommandInjection': 'Benign',
                         'DictionaryBruteForce': 'Benign', 'BenignTraffic': 'Benign'}

        self.Web = {'DDoS-RSTFINFlood': 'Benign', 'DDoS-PSHACK_Flood': 'Benign', 'DDoS-SYN_Flood': 'Benign',
                    'DDoS-UDP_Flood': 'Benign', 'DDoS-TCP_Flood': 'Benign', 'DDoS-ICMP_Flood': 'Benign',
                    'DDoS-SynonymousIP_Flood': 'Benign', 'DDoS-ACK_Fragmentation': 'Benign',
                    'DDoS-UDP_Fragmentation': 'Benign', 'DDoS-ICMP_Fragmentation': 'Benign', 'DDoS-SlowLoris': 'Benign',
                    'DDoS-HTTP_Flood': 'Benign', 'DoS-UDP_Flood': 'Benign', 'DoS-SYN_Flood': 'Benign',
                    'DoS-TCP_Flood': 'Benign', 'DoS-HTTP_Flood': 'Benign', 'Mirai-greeth_flood': 'Benign',
                    'Mirai-greip_flood': 'Benign', 'Mirai-udpplain': 'Benign', 'Recon-PingSweep': 'Benign',
                    'Recon-OSScan': 'Benign', 'Recon-PortScan': 'Benign', 'VulnerabilityScan': 'Benign',
                    'Recon-HostDiscovery': 'Benign', 'DNS_Spoofing': 'Benign', 'MITM-ArpSpoofing': 'Benign',
                    'BrowserHijacking': 'Attack', 'Backdoor_Malware': 'Attack', 'XSS': 'Attack',
                    'Uploading_Attack': 'Attack', 'SqlInjection': 'Attack', 'CommandInjection': 'Attack',
                    'DictionaryBruteForce': 'Benign', 'BenignTraffic': 'Benign'}

        self.BruteForce = {'DDoS-RSTFINFlood': 'Benign', 'DDoS-PSHACK_Flood': 'Benign', 'DDoS-SYN_Flood': 'Benign',
                           'DDoS-UDP_Flood': 'Benign', 'DDoS-TCP_Flood': 'Benign', 'DDoS-ICMP_Flood': 'Benign',
                           'DDoS-SynonymousIP_Flood': 'Benign', 'DDoS-ACK_Fragmentation': 'Benign',
                           'DDoS-UDP_Fragmentation': 'Benign', 'DDoS-ICMP_Fragmentation': 'Benign',
                           'DDoS-SlowLoris': 'Benign',
                           'DDoS-HTTP_Flood': 'Benign', 'DoS-UDP_Flood': 'Benign', 'DoS-SYN_Flood': 'Benign',
                           'DoS-TCP_Flood': 'Benign', 'DoS-HTTP_Flood': 'Benign', 'Mirai-greeth_flood': 'Benign',
                           'Mirai-greip_flood': 'Benign', 'Mirai-udpplain': 'Benign', 'Recon-PingSweep': 'Benign',
                           'Recon-OSScan': 'Benign', 'Recon-PortScan': 'Benign', 'VulnerabilityScan': 'Benign',
                           'Recon-HostDiscovery': 'Benign', 'DNS_Spoofing': 'Benign', 'MITM-ArpSpoofing': 'Benign',
                           'BrowserHijacking': 'Benign', 'Backdoor_Malware': 'Benign', 'XSS': 'Benign',
                           'Uploading_Attack': 'Benign', 'SqlInjection': 'Benign', 'CommandInjection': 'Benign',
                           'DictionaryBruteForce': 'Attack', 'BenignTraffic': 'Benign'}

        self.dict_7classes = {'DDoS-RSTFINFlood': 'DDoS', 'DDoS-PSHACK_Flood': 'DDoS', 'DDoS-SYN_Flood': 'DDoS',
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

        ### Importing Dataset
        self.df_sets = [k for k in os.listdir(self.DATASET_DIRECTORY) if k.endswith('.csv')]
        self.df_sets.sort()

        self.training_sets = self.df_sets[:int(len(self.df_sets) * .8)]
        self.test_sets = self.df_sets[int(len(self.df_sets) * .8):]
        self.X_columns = [
            'flow_duration', 'Header_Length', 'Protocol Type', 'Duration', 'Rate', 'Srate', 'Drate', 'fin_flag_number',
            'syn_flag_number', 'rst_flag_number', 'psh_flag_number', 'ack_flag_number', 'ece_flag_number',
            'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count', 'urg_count', 'rst_count', 'HTTP', 'HTTPS', 'DNS',
            'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max',
            'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Magnitue', 'Radius', 'Covariance', 'Variance', 'Weight',
        ]
        self.y_column = 'label'

        self.models = [LogisticRegression(n_jobs=-1), KNeighborsClassifier(n_neighbors=3), DecisionTreeClassifier(),
                       GaussianNB(), RandomForestClassifier(), SVC(gamma='auto')]

    def make_scaler(self):
        scaler = StandardScaler()
        for train_set in tqdm(self.training_sets):
            scaler.fit(pd.read_csv(self.DATASET_DIRECTORY + train_set)[self.X_columns])
        return scaler

    def Scaning34(self):

        scaler = self.make_scaler()

        for train_set in tqdm(self.training_sets):
            d = pd.read_csv(self.DATASET_DIRECTORY + train_set)
            d[self.X_columns] = scaler.transform(d[self.X_columns])

            self.model.fit(d[self.X_columns], d[self.y_column])

        for test_set in tqdm(self.test_sets):
            d_test = pd.read_csv(self.DATASET_DIRECTORY + test_set)
            d_test[self.X_columns] = scaler.transform(d_test[self.X_columns])
            self.y_test += list(d_test[self.y_column].values)
            self.y_pred = list(self.model.predict(d_test[self.X_columns]))

    def Scaning7(self):

        scaler = self.make_scaler()

        for train_set in tqdm(self.training_sets):
            d = pd.read_csv(self.DATASET_DIRECTORY + train_set)
            d[self.X_columns] = scaler.transform(d[self.X_columns])
            new_y = [self.dict_7classes[k] for k in d[self.y_column]]
            d[self.y_column] = new_y

            self.model.fit(d[self.X_columns], d[self.y_column])

        for test_set in tqdm(self.test_sets):
            d_test = pd.read_csv(self.DATASET_DIRECTORY + test_set)
            d_test[self.X_columns] = scaler.transform(d_test[self.X_columns])
            new_y = [self.dict_7classes[k] for k in d_test[self.y_column]]
            d_test[self.y_column] = new_y
            self.y_test += list(d_test[self.y_column].values)
            self.y_pred = list(self.model.predict(d_test[self.X_columns]))

    def scanning2(self, model):
        y_pred = []
        y_test = []
        scaler = StandardScaler()
        for train_set in tqdm(self.training_sets):
            scaler.fit(pd.read_csv(self.DATASET_DIRECTORY + train_set)[self.X_columns])

        for train_set in tqdm(self.training_sets):
            d = pd.read_csv(self.DATASET_DIRECTORY + train_set)
            d[self.X_columns] = scaler.transform(d[self.X_columns])
            new_y = [self.dict_2classes[k] for k in d[self.y_column]]
            d[self.y_column] = new_y

            model.fit(d[self.X_columns], d[self.y_column])

        for test_set in tqdm(self.test_sets):
            d_test = pd.read_csv(self.DATASET_DIRECTORY + test_set)
            d_test[self.X_columns] = scaler.transform(d_test[self.X_columns])
            new_y = [self.dict_2classes[k] for k in d_test[self.y_column]]
            d_test[self.y_column] = new_y
            y_test = list(d_test[self.y_column].values)
            y_pred = list(model.predict(d_test[self.X_columns]))

        print('#####', model, '#####')
        print('confusion matrix:\n', confusion_matrix(y_pred, y_test))
        print('accuracy_score: ', accuracy_score(y_pred, y_test))
        print('recall_score: ', recall_score(y_pred, y_test, average='macro'))
        print('precision_score: ', precision_score(y_pred, y_test, average='macro'))
        print('f1_score: ', f1_score(y_pred, y_test, average='macro'))

    def metrics(self, s):

        print(f"##### {self.models[s]} #####")
        print('confusion matrix:\n', confusion_matrix(self.y_pred, self.y_test))
        print('accuracy_score: ', accuracy_score(self.y_pred, self.y_test))
        print('recall_score: ', recall_score(self.y_pred, self.y_test, average='macro'))
        print('precision_score: ', precision_score(self.y_pred, self.y_test, average='macro'))
        print('f1_score: ', f1_score(self.y_pred, self.y_test, average='macro'))

    def run(self):

        for num, model in enumerate(self.models[:2], start=0):
            if num == 0:
                continue

            self.scanning2(model)


if __name__ == '__main__':
    IOT().run()
