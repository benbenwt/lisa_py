# coding=utf-8

from tkinter import *

import time
from tkinter import filedialog
import lisa
import json_format
import lisa_to_stix2
from stix1_to_2 import begin_convert
import xml_to_json
from validate_stix2 import convert_directory,validate_directory

LOG_LINE_NUM = 0
path1 = '/home/yoki/sdb/PycharmProjects/lisa/xml'
path2 = '/home/yoki/sdb/PycharmProjects/lisa/xml2json_result'
lisa_path='http://localhost:4242'
class MY_GUI():
    def __init__(self,init_window_name):
        self.init_window_name = init_window_name

    def set_init_window(self):
        self.init_window_name.title("xml转json批量处理")
        self.init_window_name.geometry('681x400+10+10')
        self.select_file = Button(self.init_window_name,text='选择待处理文件夹',bg='white',width=14,command=self.ask_file)   #原始数据录入框
        self.select_file.grid(row=0, column=0)
        self.result_file = Button(self.init_window_name, text='选择结果存储文件夹', bg='white', width=14,command=self.ask_result_file)  # 原始数据录入框
        self.result_file.grid(row=0, column=1)

        self.begin_button=Button(self.init_window_name,text='开始xml转json',bg='lightblue',width=14,command=self.generate)
        self.begin_button.grid(row=2,column=0)
        self.begin_button1 = Button(self.init_window_name, text='开始格式化json文件', bg='lightblue', width=14, command=self.begin_formate)
        self.begin_button1.grid(row=2,column=1)

        self.begin_button2 = Button(self.init_window_name, text='上传病毒信息', bg='lightblue', width=14, command=self.begin_lisa)
        self.begin_button2.grid(row=4, column=0)
        self.get_report = Button(self.init_window_name, text='下载报告', bg='lightblue', width=14,command=self.download_report)
        self.get_report.grid(row=4, column=1)
        self.lisa_path_entry=Entry(self.init_window_name)
        self.lisa_path_entry.grid(row=4,column=2)
        self.update_lisa_path_btn=Button(self.init_window_name,text='修改lisa_url（ip+port）',bg='lightblue',width=14,command=self.update_lisa_path)
        self.update_lisa_path_btn.grid(row=4,column=3)
        self.convert_stix2=Button(self.init_window_name,text='stix1转为stix2',bg='lightblue',width=14,command=self.begin_convert)
        self.convert_stix2.grid(row=6,column=0)
        self.validate_stix2 = Button(self.init_window_name, text='验证stix2', bg='lightblue', width=14,command=self.begin_validate)
        self.validate_stix2.grid(row=6, column=1)
        self.lisa_to_stix2_btn=Button(self.init_window_name,text='lisa_to_stix2',bg='lightblue',width=14,command=self.lisa_to_stix2)
        self.lisa_to_stix2_btn.grid(row=7)
        self.log_label = Label(self.init_window_name, text="日志")
        self.log_label.grid(row=20, column=0)
        self.log_data_Text = Text(self.init_window_name, width=66, height=9)  # 日志框
        self.log_data_Text.grid(row=25, column=0, columnspan=10)
        self.write_log_to_Text('待处理文件夹默认选中xml存储文件夹')
        self.write_log_to_Text('结果默认存放在'+path2)

    def lisa_to_stix2(self):
        lisa_to_stix2.convert_to_stix2(path1, path2)
        self.write_log_to_Text('转换完成')

    def update_lisa_path(self):
        global lisa_path
        lisa_path=self.lisa_path_entry.get()
        print(lisa_path)

    def begin_convert(self):
        begin_convert(path1,path2)
        self.write_log_to_Text("转换完成")

    def begin_validate(self):
        result_list=validate_directory(path1)
        for result in result_list:
            self.write_log_to_Text(result)
        self.write_log_to_Text('验证完成')

    def ask_file(self):
        global path1
        path1=filedialog.askdirectory()
        # print(path1)
        try:
            self.write_log_to_Text('sourcefile:'+path1)
        except Exception:
            print('未选中文件夹')

    def ask_result_file(self):
        global path2
        path2=filedialog.askdirectory()
        # print(path2)
        try:
            self.write_log_to_Text('resultfiel:' + path2)
        except Exception:
            print('未选中文件夹')

    def generate(self):
        xml_to_json.xml2_json(path1, path2)
        print('success')
        self.write_log_to_Text('转换完成，请到结果文件夹查看')

    def begin_lisa(self):
        id_list = lisa.get_id_list(path1,lisa_path)
        self.id_list=id_list
        print('waiting for  analyze....')
        self.write_log_to_Text('请勿操作,' + str(len(id_list)*30)+'秒后来下载报告')

    def download_report(self):
        self.write_log_to_Text('下载中......')
        try:
            lisa.get_report_list(lisa_path, id_list=self.id_list,path=path2)
        except Exception:
            print('请先上传病毒再下载报告')
        print('下载完成')
        self.write_log_to_Text('下载成功，请到结果文件夹查看')
        self.write_log_to_Text('若报告内容无效，请等待分析完成再次下载')

    def begin_formate(self):
        try:
            json_format.json_formate(path1, path2)
        except ValueError as e:
            print("所选文件夹非json文件")
            self.write_log_to_Text('所选文件夹非json文件')
            return
        print('success')
        self.write_log_to_Text('转换完成，请到结果文件夹查看')


    def get_current_time(self):
        current_time = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        return current_time

    def write_log_to_Text(self, logmsg):
        global LOG_LINE_NUM
        current_time = self.get_current_time()
        logmsg_in = str(current_time) + " " + str(logmsg) + "\n"  # 换行
        if LOG_LINE_NUM <= 20:
            self.log_data_Text.insert(END, logmsg_in)
            LOG_LINE_NUM = LOG_LINE_NUM + 1
        else:
            self.log_data_Text.delete(1.0, 2.0)
            self.log_data_Text.insert(END, logmsg_in)


def gui_start():
    init_window = Tk()
    ZMJ_PORTAL = MY_GUI(init_window)
    # 设置根窗口默认属性
    ZMJ_PORTAL.set_init_window()

    init_window.mainloop()

if __name__=="__main__":
    gui_start()

