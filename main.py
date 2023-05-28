# Training a ML model using CICIoT2023

import os
import warnings

import pandas as pd
from tqdm import tqdm

warnings.filterwarnings('ignore')

from sklearn.linear_model import LogisticRegression

DATASET_DIRECTORY = '/home/debian/PycharmProjects/iot/'
### Importing Dataset
df_sets = [k for k in os.listdir(DATASET_DIRECTORY) if k.endswith('.csv')]

df_sets.sort()

training_sets = df_sets[:int(len(df_sets) * .8)]

test_sets = df_sets[int(len(df_sets) * .8):]
X_columns = [

    'flow_duration', 'Header_Length', 'Protocol Type', 'Duration',

    'Rate', 'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number',

    'rst_flag_number', 'psh_flag_number', 'ack_flag_number',

    'ece_flag_number', 'cwr_flag_number', 'ack_count',

    'syn_count', 'fin_count', 'urg_count', 'rst_count',

    'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP',

    'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min',

    'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Magnitue',

    'Radius', 'Covariance', 'Variance', 'Weight',

]

y_column = 'label'
### Scaling
from sklearn.preprocessing import StandardScaler

scaler = StandardScaler()
for train_set in tqdm(training_sets):
    scaler.fit(pd.read_csv(DATASET_DIRECTORY + train_set)[X_columns])
### Classification: 34 (33+1) classes
ML_models = [

    LogisticRegression(n_jobs=-1),

]

ML_neams = [

    "LogisticRegression",

]

for train_set in tqdm(training_sets):

    d = pd.read_csv(DATASET_DIRECTORY + train_set)

    d[X_columns] = scaler.transform(d[X_columns])

    for model in (ML_models):
        model.fit(d[X_columns], d[y_column])

    del d
y_test = []

preds = {i: [] for i in range(len(ML_models))}

for test_set in tqdm(test_sets):

    d_test = pd.read_csv(DATASET_DIRECTORY + test_set)

    d_test[X_columns] = scaler.transform(d_test[X_columns])

    y_test += list(d_test[y_column].values)

    for i in range(len(ML_models)):
        model = ML_models[i]

        y_pred = list(model.predict(d_test[X_columns]))

        preds[i] = preds[i] + y_pred

from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score

for k, v in preds.items():
    y_pred = v

    print(f"##### {ML_neams[k]} (34 classes) #####")

    print('accuracy_score: ', accuracy_score(y_pred, y_test))

    print('recall_score: ', recall_score(y_pred, y_test, average='macro'))

    print('precision_score: ', precision_score(y_pred, y_test, average='macro'))

    print('f1_score: ', f1_score(y_pred, y_test, average='macro'))

dict_7classes = {'DDoS-RSTFINFlood': 'DDoS', 'DDoS-PSHACK_Flood': 'DDoS', 'DDoS-SYN_Flood': 'DDoS',
                 'DDoS-UDP_Flood': 'DDoS', 'DDoS-TCP_Flood': 'DDoS', 'DDoS-ICMP_Flood': 'DDoS',
                 'DDoS-SynonymousIP_Flood': 'DDoS', 'DDoS-ACK_Fragmentation': 'DDoS', 'DDoS-UDP_Fragmentation': 'DDoS',
                 'DDoS-ICMP_Fragmentation': 'DDoS', 'DDoS-SlowLoris': 'DDoS', 'DDoS-HTTP_Flood': 'DDoS',
                 'DoS-UDP_Flood': 'DoS', 'DoS-SYN_Flood': 'DoS', 'DoS-TCP_Flood': 'DoS', 'DoS-HTTP_Flood': 'DoS',
                 'Mirai-greeth_flood': 'Mirai', 'Mirai-greip_flood': 'Mirai', 'Mirai-udpplain': 'Mirai',
                 'Recon-PingSweep': 'Recon', 'Recon-OSScan': 'Recon', 'Recon-PortScan': 'Recon',
                 'VulnerabilityScan': 'Recon', 'Recon-HostDiscovery': 'Recon', 'DNS_Spoofing': 'Spoofing',
                 'MITM-ArpSpoofing': 'Spoofing', 'BenignTraffic': 'Benign', 'BrowserHijacking': 'Web',
                 'Backdoor_Malware': 'Web', 'XSS': 'Web', 'Uploading_Attack': 'Web', 'SqlInjection': 'Web',
                 'CommandInjection': 'Web', 'DictionaryBruteForce': 'BruteForce'}

from sklearn.linear_model import LogisticRegression

ML_models = [

    LogisticRegression(n_jobs=-1),

]

ML_neams = [

    "LogisticRegression",

]

for train_set in tqdm(training_sets):

    d = pd.read_csv(DATASET_DIRECTORY + train_set)

    d[X_columns] = scaler.transform(d[X_columns])

    new_y = [dict_7classes[k] for k in d[y_column]]

    d[y_column] = new_y

    for model in (ML_models):
        model.fit(d[X_columns], d[y_column])

    del d
y_test = []

preds = {i: [] for i in range(len(ML_models))}

for test_set in tqdm(test_sets):

    d_test = pd.read_csv(DATASET_DIRECTORY + test_set)

    d_test[X_columns] = scaler.transform(d_test[X_columns])

    new_y = [dict_7classes[k] for k in d_test[y_column]]

    d_test[y_column] = new_y

    y_test += list(d_test[y_column].values)

    for i in range(len(ML_models)):
        model = ML_models[i]

        y_pred = list(model.predict(d_test[X_columns]))

        preds[i] = preds[i] + y_pred

from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score

for k, v in preds.items():
    y_pred = v

    print(f"##### {ML_neams[k]} (8 classes) #####")

    print('accuracy_score = ', accuracy_score(y_pred, y_test))

    print('recall_score = ', recall_score(y_pred, y_test, average='macro'))

    print('precision_score = ', precision_score(y_pred, y_test, average='macro'))

    print('f1_score = ', f1_score(y_pred, y_test, average='macro'))


# Classification: 2 (1+1) Classes
dict_2classes = {'DDoS-RSTFINFlood': 'Attack', 'DDoS-PSHACK_Flood': 'Attack', 'DDoS-SYN_Flood': 'Attack',
                 'DDoS-UDP_Flood': 'Attack', 'DDoS-TCP_Flood': 'Attack', 'DDoS-ICMP_Flood': 'Attack',
                 'DDoS-SynonymousIP_Flood': 'Attack', 'DDoS-ACK_Fragmentation': 'Attack',
                 'DDoS-UDP_Fragmentation': 'Attack', 'DDoS-ICMP_Fragmentation': 'Attack', 'DDoS-SlowLoris': 'Attack',
                 'DDoS-HTTP_Flood': 'Attack', 'DoS-UDP_Flood': 'Attack', 'DoS-SYN_Flood': 'Attack',
                 'DoS-TCP_Flood': 'Attack', 'DoS-HTTP_Flood': 'Attack', 'Mirai-greeth_flood': 'Attack',
                 'Mirai-greip_flood': 'Attack', 'Mirai-udpplain': 'Attack', 'Recon-PingSweep': 'Attack',
                 'Recon-OSScan': 'Attack', 'Recon-PortScan': 'Attack', 'VulnerabilityScan': 'Attack',
                 'Recon-HostDiscovery': 'Attack', 'DNS_Spoofing': 'Attack', 'MITM-ArpSpoofing': 'Attack',
                 'BenignTraffic': 'Benign', 'BrowserHijacking': 'Attack', 'Backdoor_Malware': 'Attack', 'XSS': 'Attack',
                 'Uploading_Attack': 'Attack', 'SqlInjection': 'Attack', 'CommandInjection': 'Attack',
                 'DictionaryBruteForce': 'Attack'}

from sklearn.linear_model import LogisticRegression

ML_models = [

    LogisticRegression(n_jobs=-1),

]

ML_neams = [

    "LogisticRegression",

]

for train_set in tqdm(training_sets):

    d = pd.read_csv(DATASET_DIRECTORY + train_set)

    d[X_columns] = scaler.transform(d[X_columns])

    new_y = [dict_2classes[k] for k in d[y_column]]

    d[y_column] = new_y

    for model in (ML_models):
        model.fit(d[X_columns], d[y_column])

    del d
y_test = []

preds = {i: [] for i in range(len(ML_models))}

for test_set in tqdm(test_sets):

    d_test = pd.read_csv(DATASET_DIRECTORY + test_set)

    d_test[X_columns] = scaler.transform(d_test[X_columns])

    new_y = [dict_2classes[k] for k in d_test[y_column]]

    d_test[y_column] = new_y

    y_test += list(d_test[y_column].values)

    for i in range(len(ML_models)):
        model = ML_models[i]

        y_pred = list(model.predict(d_test[X_columns]))

        preds[i] = preds[i] + y_pred

from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score


for k, v in preds.items():
    y_pred = v

    print(f"##### {ML_neams[k]} (2 classes) #####")
    print('accuracy_score: ', accuracy_score(y_pred, y_test))
    print('recall_score: ', recall_score(y_pred, y_test, average='macro'))
    print('precision_score: ', precision_score(y_pred, y_test, average='macro'))
    print('f1_score: ', f1_score(y_pred, y_test, average='macro'))
