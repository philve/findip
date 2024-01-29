from PySide2.QtWidgets import QApplication, QMessageBox,QTextEdit
from PySide2.QtUiTools import QUiLoader
from PySide2.QtGui import *
from PySide2.QtCore import QFile
from info_basic import withoutwww
from info_basic import iscdn
from info_basic import history_ip
from info_basic import  domain_handler
from info_basic import domain_short
import requests
import mmh3
from shodan import Shodan
import config
import base64

#from shodan_ico import queryshodan
#from scan import cer_scan
#from scan import simple_tasks
# from scan import subdomainandcers
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
import queue
import dns.resolver
import requests
import base64
import re
import urllib
green = '\033[01;32m'
# blue = '\033[01;34m'
red = '\033[1;31m'
green = '\033[01;32m'

def dict_score(dict1,list1,score):
    for i in list1:
        dict1.setdefault(i,0)
        dict1[i] += score
    return dict1
def stander_output(way,list):
    if len(list)==0:
        return way+"No IP addresses found"
    return way+"Found "+str(len(list))+"IP addresses"+'\n'+'\n'.join(x for x in list)+"\n"


def res_output(list1,list2,list3):
    text=""
    if len(list1):
        text+="Max possible IPs: "+str(len(list1))+"个"
        text+="\n"
        for i in list1[:-1]:
            text+=i+","
        text+=list1[-1]
        text += "\n"

    if len(list2):
        text+="Comparatively possible IPs"+str(len(list2))+"个"
        text+="\n"
        for i in list2[:-1]:
            text+=i+","
        text+=list2[-1]
        text += "\n"
    if len(list3):
        text+="Possibly matching IPs: "+str(len(list3))+"个"
        text+="\n"
        for i in list3[:-1]:
            text+=i+","
        text+=list3[-1]
        text += "\n"
    return text
from PySide2.QtCore import Signal,QObject

class MySignals(QObject):
    # Define a signal with two parameters: QTextBrowser and string
    text_print = Signal(QTextEdit,str)
    to_sign=Signal(str)

class Stats:
    def setupUi(self, Form):
        from PySide2 import QtCore
        Form.setObjectName("Form")
        Form.resize(436, 652)
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(Form)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.queryline = QtWidgets.QLineEdit(Form)
        self.queryline.setObjectName("queryline")
        self.horizontalLayout.addWidget(self.queryline)
        self.method = QtWidgets.QComboBox(Form)
        self.method.setObjectName("method")
        self.method.addItems(['Scan using all methods', 'Scan without API', 'Scan using only API'])
        self.horizontalLayout.addWidget(self.method)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.tabWidget = QtWidgets.QTabWidget(Form)
        self.tabWidget.setObjectName("tabWidget")
        self.tab_1 = QtWidgets.QWidget()
        self.tab_1.setObjectName("tab_1")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.tab_1)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.resulttext = QtWidgets.QTextEdit(self.tab_1)
        self.resulttext.setObjectName("resulttext")
        self.verticalLayout_4.addWidget(self.resulttext)
        self.yzbutton = QtWidgets.QPushButton(self.tab_1)
        self.yzbutton.setObjectName("yzbutton")
        self.verticalLayout_4.addWidget(self.yzbutton)
        self.tabWidget.addTab(self.tab_1, "")
        self.tab_2 = QtWidgets.QWidget()

        self.tab_2.setObjectName("tab_2")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.tab_2)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.parseinfo = QtWidgets.QTextEdit(self.tab_2)
        self.parseinfo.setObjectName("parseinfo")
        self.verticalLayout_5.addWidget(self.parseinfo)
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.tab_3)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.sameinfo = QtWidgets.QTextEdit(self.tab_3)
        self.sameinfo.setObjectName("sameinfo")
        self.verticalLayout_6.addWidget(self.sameinfo)
        self.tabWidget.addTab(self.tab_3, "")
        self.verticalLayout.addWidget(self.tabWidget)
        self.verticalLayout_2.addLayout(self.verticalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.querybtn = QtWidgets.QPushButton(Form)
        self.querybtn.setObjectName("querybtn")
        self.horizontalLayout_2.addWidget(self.querybtn)
        self.clearbtn = QtWidgets.QPushButton(Form)
        self.clearbtn.setObjectName("clearbtn")
        self.horizontalLayout_2.addWidget(self.clearbtn)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.verticalLayout_3.addLayout(self.verticalLayout_2)
        self.pool=ThreadPoolExecutor()
        # self.ui = QUiLoader().load('cdn.ui') # load returns the window object
        # Add data through load
        #
        self.querybtn.clicked.connect(self.handleCalc) # Define signal processing, associate processing functions with objects
        # self.ui.method.addItem('Scan using all methods')
        # self.ui.method.addItem('post')
        # self.ui.method.addItem('delete')
        self.yzbutton.clicked.connect(self.yzfunc)
        self.ms = MySignals()
        self.ms.text_print.connect(self.printToGui)
        self.ms.to_sign.connect(self.signdeal)
        self.all=0
        self.done=0
        self.find=0


        self.pool.submit(self.yzfunc)
        self.retranslateUi(Form)
        self.tabWidget.setCurrentIndex(0)
        self.clearbtn.clicked.connect(self.clearall)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def signdeal(self,str):
        print('x')
        if str=="done":
            self.done+=1
        if str=="find":
            self.find+=1


        print(f"done____{self.done}")
        print(f"find-----{self.find}")
        if self.done==self.all:
            if self.find==0:
                self.ms.text_print.emit(self.resulttext, "No IP found")

            else:
                self.ms.text_print.emit(self.resulttext,"Query completed")



    def retranslateUi(self, Form):
        from PySide2 import QtCore
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "IP Address Query Tool"))
        self.yzbutton.setText(_translate("Form", "Click to Verify"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_1), _translate("Form", "Overall Results"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("Form", "Parsing Information Collection"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("Form", "Identical Information Collection"))
        self.querybtn.setText(_translate("Form", "Query"))
        self.clearbtn.setText(_translate("Form", "Clear"))


    def __init__(self):
        pass
        # self.pool=ThreadPoolExecutor()
        # # self.ui = QUiLoader().load('cdn.ui') # The data returned by load is the window object
        # # Add data through load
        # #
        # self.querybtn.clicked.connect(self.handleCalc) #Define signal processing and map processing functions to objects
        # # self.ui.method.addItem('Scan all')
        # # self.ui.method.addItem('post')
        # # self.ui.method.addItem('delete')
        # self.yzbutton.clicked.connect(self.yzfunc)
        # self.ms = MySignals()
        # self.ms.text_print.connect(self.printToGui)
        #
        # self.pool.submit(self.yzfunc)


    def printToGui(self,fb,text):
        fb.append(str(text))

    def clearall(self):
        self.resulttext.clear()
        self.parseinfo.clear()
        self.sameinfo.clear()

    def handleCalc(self):
        print("执行handleClc")
        self.domain= self.queryline.text()
        self.metho = self.method.currentText()

        ip_lis=[]
        # self.withoutwww_m(domain)
        # self.dns_m(domain)
        self.pool.submit(self.func,self.domain)
        # self.sametitle(domain)


    def func(self,domain):
        print(self.metho)
        if self.metho=="Scan using all methods":
            print("Already executed")
            try:
                # samecer_job=self.pool.submit(self.samecer,domain)
                sametitle_job=self.pool.submit(self.sametitle,domain)
                sameico_job = self.pool.submit(self.sameico, domain)

                withoutwww_job=self.pool.submit(self.withoutwww,domain)
                dns_job=self.pool.submit(self.dns,domain)
                dict1={}
                #
                # print(dns_job.result())
                # print(withoutwww_job.result())
                # print(sametitle_job.result())
                # print(samecer_job.result())

                dict1=dict_score(dict1,dns_job.result(),1)
                dict1 = dict_score(dict1, withoutwww_job.result(),5)
                dict1 = dict_score(dict1, sametitle_job.result(),5 )
                # dict1 = dict_score(dict1, samecer_job.result(), 3)
                dict1 = dict_score(dict1, sameico_job.result(), 6)
                list1=sorted(dict1.items())
                res_max=[]
                res_med=[]
                res_min=[]
                for a in list1:
                    if a[1]>10:
                        res_max.append(a[0])
                    elif a[1]>5:
                        res_med.append(a[0])
                    elif a[1]>3:
                        res_min.append(a[0])
                print(res_output(res_max,res_med,res_min))
                print(type(res_output(res_max,res_med,res_min)))
                self.res_max=res_max
                self.res_med=res_med
                self.res_min = res_min

                self.ms.text_print.emit(self.resulttext,res_output(res_max,res_med,res_min))
                self.ms.text_print.emit(self.resulttext, "Search complete, consider verification")
            except:
                pass

        elif self.metho == "Scan without API":
            try:
                dict2 = {}
                withoutwww_job=self.pool.submit(self.withoutwww,domain)
                dns_job=self.pool.submit(self.dns,domain)
                dict2=dict_score(dict2,dns_job.result(),1)
                dict2 = dict_score(dict2, withoutwww_job.result(),5)
                list1=sorted(dict2.items())
                res_max=[]
                res_med=[]
                res_min=[]
                for a in list1:
                    if a[1]>10:
                        res_max.append(a[0])
                    elif a[1]>5:
                        res_med.append(a[0])
                    elif a[1]>3:
                        res_min.append(a[0])
                print(res_output(res_max,res_med,res_min))
                print(type(res_output(res_max,res_med,res_min)))
                self.res_max=res_max
                self.res_med=res_med
                self.res_min = res_min

                self.ms.text_print.emit(self.resulttext,res_output(res_max,res_med,res_min))
                self.ms.text_print.emit(self.resulttext, "Search complete, consider verification")

            except:
                pass
        elif self.metho == "Scan using only API":
            try:
                dict3 = {}
                withoutwww_job=self.pool.submit(self.withoutwww,domain)
                dns_job=self.pool.submit(self.dns,domain)
                dict3=dict_score(dict3,dns_job.result(),1)
                dict3 = dict_score(dict3, withoutwww_job.result(),5)
                list1=sorted(dict3.items())
                res_max=[]
                res_med=[]
                res_min=[]
                for a in list1:
                    if a[1]>10:
                        res_max.append(a[0])
                    elif a[1]>5:
                        res_med.append(a[0])
                    elif a[1]>3:
                        res_min.append(a[0])
                print(res_output(res_max,res_med,res_min))
                print(type(res_output(res_max,res_med,res_min)))
                self.res_max=res_max
                self.res_med=res_med
                self.res_min=res_min

                self.ms.text_print.emit(self.resulttext,res_output(res_max,res_med,res_min))
                self.ms.text_print.emit(self.resulttext, "Search complete, consider verification")

            except:
                pass


    def yzfunc(self):
        from scan import simple_task
        print("Start verification!")
        simple_task(self,"http://"+self.domain,self.res_max+self.res_med+self.res_min)


        pass


    def withoutwww(self,domain):
        # q1=queue.Queue(10)
        # def rock(domain,ip_lis):
        ip_lis=[]
        domain = domain.lstrip('www.')
        try:
            ans = dns.resolver.query(domain, 'A')  # Query through DNS
            print(type(ans))
            if ans:
                for i in ans.response.answer[-1].items:
                    if i.address in ip_lis:
                        continue
                    ip_lis.append(i.address)
        except:
            pass
        self.ms.text_print.emit(self.parseinfo, stander_output('Searching for sites without www',ip_lis))
        return ip_lis
            # for i in  ip_lis:
            #     q1.put(i)




    def dns(self,domain):
        ip_lis=[]
        ans = dns.resolver.query(domain, 'A')  # Query through DNS
        if ans:
            for i in ans.response.answer[-1].items:
                if i.address in ip_lis:
                    continue
                ip_lis.append(i.address)
        self.ms.text_print.emit(self.parseinfo, stander_output('DNS resolution', ip_lis))
        return ip_lis
        # thread = Thread(target=rock, args=(domain, []))
        # thread.start()

    # def samecer(self,domain):
    #     import json
    #     # from scan import cert2iplis
    #     # q3=queue.Queue(100)
    # # def rocksamecer(domain):
    #     import config
    #     import censys
    #     domain = domain.lstrip('www.')
    #     hash=base64.b64encode(domain.encode("utf-8")).decode("utf-8")
    #
    #     # import gevent
    #     # from gevent import monkey
    #     # monkey.patch_all()
    #     UID = config.censys_uid
    #     SECRET = config.censys_secret
    #     ip_lis = []
    #     certificates = censys.certificates.CensysCertificates(UID, SECRET)
    #     cert_lis = []
    #     fields = ["parsed.fingerprint_sha256"]
    #     query_str = "parsed.names: " + domain + " and tags.raw: trusted"
    #     for c in certificates.search(query_str, fields=fields):
    #         cert_lis.append(c["parsed.fingerprint_sha256"])
    #
    #     for cert in cert_lis:
    #         cert2iplis(cert, ip_lis)
    #     self.ms.text_print.emit(self.ui.sameinfo, stander_output('Resolved through the same certificate', ip_lis))
    #     return ip_lis

    #     # res = set(list(json.loads(r.text)))
    #     # self.ms.text_print.emit(self.ui.sameinfo, stander_output('Resolving via the same certificate', res))
    #     # return res


    def sametitle(self,domain):
        # def rocksametitle(domain):
        header = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36',
            #'Referer': 'http://www.4399.com/'
        }
        url="http://"+domain
        r = requests.get(url, header)
        res1 = re.search(r'meta.*?charset=(.*?)"', r.text)
        if res1 == None:
            print(f'{red}No encoding found for the target site, defaulting to utf-8')
            r.encoding = 'utf-8'

        elif res1:
            print(f'{green}Found encoding for the target site: {res1.group(1)}')

        r = requests.get(url, header)
        r.encoding = res1.group(1)
        res = re.search(r'<title>(.*?)</title>', r.text)

        title = "title=" + "\"" + res.group(1) + "\""

        rawurl = "https://fofa.so/result?q=" + urllib.parse.quote(title)
        r = requests.get(rawurl)
        regx = re.compile(r'/hosts/(.*?)">')
        rs = regx.findall(r.text)
        self.ms.text_print.emit(self.sameinfo, stander_output('Parsing using the same title', rs))
        #return ip_lis
        return  rs
        # thread = Thread(target=rocksametitle, args=(domain,))
        # thread.start()



    def getfaviconhash(self,url):
        try:
            response = requests.get(url)
            # print(response.headers)
            if response.headers['Content-Type'] == "image/x-icon":
                #  favicon = response.content.encode('base64')
                data = base64.encodebytes(response.content)
                hash = mmh3.hash(str(data, encoding='utf-8'))
            else:
                hash = None
        except:
            hash = None
        return hash

    def sameico(self,url):
        import json
        '''
        Use shodan to find and target websites using the same icon
        :param url: visited url
        :param ip_lis: Add the ip_lis and finally return it
        :return:
        '''
        print("Start searching for websites with the same icon")

        url = "http://"+url
        api = Shodan(config.shodan_api)

        url = url + "/favicon.ico"
        res=[]
        try:
            hash = self.getfaviconhash(url)

            if hash:

                query = "http.favicon.hash:{}".format(hash)
                # print(query)

                print("[+] The same ico get")
                for hosts in api.search_cursor(query):
                    res.append(hosts['ip_str'])

                return res

        except:
            pass
        print("Search for websites with the same icon complete. Found " + str(len(res)))
        self.ms.text_print.emit(self.sameinfo, stander_output('Finding websites with the same icon', res))
        return res

if __name__ == '__main__':
    import sys
    from PySide2 import QtWidgets

    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QWidget()
    ui =Stats()
    ui.setupUi(MainWindow)
    # ui.retranslateUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
