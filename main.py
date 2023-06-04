# Training a ML model using CICIoT2023
import pandas as pd
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
        self.DATASET_DIRECTORY = '/home/debian/PycharmProjects/iot/'

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

        self.metrics(model, y_pred, y_test)

    def metrics(self, model, y_pred, y_test):

        print(f"##### {model} #####")
        print('confusion matrix:\n', confusion_matrix(y_pred, y_test))
        print('accuracy_score: ', accuracy_score(y_pred, y_test))
        print('recall_score: ', recall_score(y_pred, y_test, average='macro'))
        print('precision_score: ', precision_score(y_pred, y_test, average='macro'))
        print('f1_score: ', f1_score(y_pred, y_test, average='macro'))

    def run(self):
        for num, model in enumerate(self.models, start=0):
            self.scanning2(model)


from customtkinter import *
from time import sleep
import sys
import threading


class IotMock:
    @staticmethod
    def scanning2(model, attack):
        print('starting...', model, attack)
        for i in range(3):
            sleep(1)
            print(i)
        print('doing...')
        sleep(1)
        print('done!')


class TextRedirector:

    def __init__(self, widget, tag="stdout"):
        self.widget = widget
        self.tag = tag
        self.output = ''

    def write(self, str):
        self.output += str
        self.widget.configure(state="normal")
        self.widget.insert("end", str)
        self.widget.configure(state="disabled")

    def flush(self):
        pass


class App(CTk):
    attacks = [
        "BruteForce",
        "Web",
        "Spoofing",
        "Recon",
        "Mirai",
        "DOS",
        "DDOS",
    ]
    attack = attacks[0]

    methods = [
        "Логистическая регрессия",
        "К - ближайших соседей",
        "Дерево принятия решений",
        "Наивная байесовская классификация",
        "Метод случайного леса",
        "Метод опорных векторов",
    ]
    method = methods[0]

    iot = IotMock()

    height = 600
    width = 600
    color = '#522878'

    def __init__(self):
        super().__init__()
        self.title('IOT GUI')
        # self.resizable(True, True)
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=2)
        self.rowconfigure(0, weight=1)

        self.left_frame = CTkFrame(self)
        CTkLabel(self.left_frame, text='Лог:').grid(row=0, column=0)
        self.text = CTkTextbox(self.left_frame)
        self.text.grid(row=1, column=0)
        self.left_frame.grid(row=0, column=0)

        self.right_frame = CTkFrame(self)
        CTkLabel(self.right_frame, text='Выбор атаки:').grid(row=0, column=0)
        CTkOptionMenu(self.right_frame,
                      values=self.attacks,
                      command=lambda choice: self.choose_attack(choice),
                      fg_color=self.color,
                      button_color=self.color).grid(row=1, column=0)
        CTkLabel(self.right_frame, text='Выбор метода:').grid(row=2, column=0)
        CTkOptionMenu(self.right_frame,
                      values=self.methods,
                      command=lambda choice: self.choose_method(choice),
                      fg_color=self.color,
                      button_color=self.color).grid(row=3, column=0)
        CTkLabel(self.right_frame, text='').grid(row=4, column=1)
        CTkButton(self.right_frame, text='Сохранить лог', )
        CTkButton(self.right_frame, text='Start', command=self.run, fg_color=self.color).grid(row=5, column=0)

        self.right_frame.grid(row=0, column=1)
        self.redirect = TextRedirector(self.text, "stdout")
        sys.stdout = self.redirect

    def save_log(self):
        with open('log.txt', 'w') as file:
            file.write(self.redirect.output)

    def run(self):
        threading.Thread(target=self.iot.scanning2, daemon=True, args=(self.method, self.attack)).start()

    def choose_attack(self, choice):
        self.attack = choice

    def choose_method(self, choice):
        self.method = choice


if __name__ == '__main__':
    app = App()
    app.mainloop()
