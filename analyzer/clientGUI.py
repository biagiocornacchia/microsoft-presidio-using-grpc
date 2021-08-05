import analyzer_client as analyzer

from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk

import json

import os
from pathlib import Path

IP_ADDRESS = "localhost"
PORT = "8061"

ENGINE_CURR_OPTIONS = {}
ANALYZE_CURR_OPTIONS = {'language':'en', 'entities': None, 'correlation_id': None, 'score_threshold': "0.1", 'return_decision_process': "0" }
DENY_LIST = {'supported_entities': [], 'valuesList': [], 'length': 0 }
REGEX_LIST = {'entities': [], 'names_pattern': [], 'patterns': [], 'scores': [], 'context_words': [], 'length': 0 }

class Frames(object):

    def __init__(self, root):
        self.root = root
        self.root.title('Presidio Analyzer gRPC Client')
        self.root.geometry('650x260')
        self.root.configure(bg="#0B0C10")
        self.root.resizable(0, 0)        

        # Title
        frameTitle = Frame(self.root, width = 650, height = 60, bg="#0B0C10")
        frameTitle.grid(row = 0, columnspan = 2)

        Label(frameTitle, text="Microsoft Presidio Analyzer", font=("Helvetica", 17, "bold"), bg="#0B0C10", fg="#C5C6C7", anchor = CENTER).pack(ipady = 20)

        # Settings
        frameBtnSettings = Frame(self.root, bg="#0B0C10")
        frameBtnSettings.grid(row = 2, columnspan = 2)

        settingsButton = Button(frameBtnSettings, text="Settings", font=("Helvetica", 14), bg="#0B0C10", fg="#C5C6C7", command = self.settings).pack(pady = 10, ipadx= 33, ipady = 3)

        # Start analyzer
        frameBtnAnalyze = Frame(self.root, width = 650, height = 1, bg="#0B0C10")
        frameBtnAnalyze.grid(row = 1, columnspan = 2)

        analyzeBtn = Button(frameTitle, text="Start analyzer", font=("Helvetica", 14), bg="#0B0C10", fg="#C5C6C7", command = self.startAnalyzer).pack(pady = 22, ipadx= 10, ipady = 3)

    def startAnalyzer(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = Path(dir_path)

        self.root.filenames = filedialog.askopenfilenames(initialdir= str(path.parent.absolute()) + "/files", title="Select A File", filetypes=(("txt files", "*.txt"),("all files", "*.*")))
        
        if self.root.filenames:
            clientAnalyzer = analyzer.ClientEntity(IP_ADDRESS, PORT)

            # send options if setted
            for elem in ANALYZE_CURR_OPTIONS:
                clientAnalyzer.setupOptions(elem, ANALYZE_CURR_OPTIONS[elem], "ANALYZE_OPTIONS")

            if DENY_LIST['length'] > 0:
                clientAnalyzer.setupDenyList(DENY_LIST['supported_entities'], DENY_LIST['valuesList'])
                     
            if REGEX_LIST['length'] > 0:
                patterns = analyzer.createPatternInfo(1, REGEX_LIST['names_pattern'], REGEX_LIST['patterns'], REGEX_LIST['scores'])
                clientAnalyzer.setupRegex(REGEX_LIST['entities'][0], patterns, REGEX_LIST['context_words'][0])

            progressWindow = Toplevel()
            progressWindow.title("Analyzer Status")
            progressWindow.geometry("330x80")
            progressWindow.configure(bg="white")
            self.root.update_idletasks()

            Label(progressWindow, text="Analyzer process is starting..it may take a while!", font=("Helvetica", 10), bg="white", fg="black").pack(side=TOP, padx = 15, pady = 7)
            progressBar = ttk.Progressbar(progressWindow, orient=HORIZONTAL, length=200, mode="determinate")
            progressBar.pack(side=TOP, pady = 14)
            self.root.update_idletasks()

            filenameList = []
            for path in self.root.filenames:

                filename, ext = os.path.basename(path).split(".")
                filenameList.append(filename)

                res = clientAnalyzer.sendRequestAnalyze(os.path.basename(filename))
                
                if res == -2:
                    progressWindow.destroy()
                    messagebox.showerror("gRPC Server Error", "Cannot connect to the server! Check your server settings")
                    break
                
                if progressBar['value'] < 100:
                    progressBar['value'] += (100/len(self.root.filenames))
                    self.root.update_idletasks()
                
                if int(progressBar['value']) == 100:
                    messagebox.showinfo(parent=progressWindow, message='Analyzer process completed!')
                    progressWindow.destroy()

            if res != -2:
                clientAnalyzer.closeConnection()
                self.readResults(filenameList)

    def readResults(self, filenameList):
        self.result = Toplevel()
        self.result.title("Presidio Analyzer gRPC - RESULTS")
        self.result.geometry("850x450")
        self.result.configure(bg="#0B0C10")
        self.result.resizable(0, 0)

        ## List filename-results.txt
        frameList = Frame(self.result, width = 150, height = 30)
        frameList.pack(side=LEFT, padx=13)

        # Scrollbar
        resultsScrollbar = Scrollbar(frameList, orient=VERTICAL)

        listbox_widget = Listbox(frameList, yscrollcommand=resultsScrollbar.set, height = 20, font=("Courier", 12), bg="#1F2833", fg="#C5C6C7")
        
        # configure scrollbar
        resultsScrollbar.config(command=listbox_widget.yview)
        resultsScrollbar.pack(side=RIGHT, fill=Y)
        ## END LIST

        ## Frame that will contain results
        frameResults = Frame(self.result, width = 680, bg="#0B0C10")
        frameResults.pack(side=RIGHT, pady = 15, padx = 10)
        
        self.text_widget = Text(frameResults, font=("Courier", 13), spacing1=3, bg="#1F2833", fg="#C5C6C7")
        self.text_widget.pack(pady = 10, padx= 15)
        ## END FRAME
        
        for filename in filenameList:
            listbox_widget.insert(END, filename)

        listbox_widget.bind('<<ListboxSelect>>', self.clickEvent)
        listbox_widget.pack()

    def clickEvent(self, e):
	
        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = Path(dir_path)

        currSelection = e.widget.curselection()
        filename = e.widget.get(currSelection)
        #print(filename)

        with open(str(path.parent.absolute()) + "/files/" + filename + ".txt", "r") as originalFile:
            
            originalText = originalFile.read()

            with open(str(path.parent.absolute()) + "/analyzer-results/" + filename + "-results.txt", "r") as resultsFile:

                self.text_widget.configure(state='normal')
                self.text_widget.delete("1.0", END)

                for line in resultsFile:
                    resultStr = json.loads(line)
                    #print(resultStr)
                    start = resultStr['start']
                    end = resultStr['end']

                    self.text_widget.insert(END, f"FOUND WORD: {originalText[start:end]}\n\n")
                    self.text_widget.insert(END, f"ENTITY TYPE: {resultStr['entity_type']}\nSTART: {resultStr['start']}\nEND: {resultStr['end']}\nSCORE: {resultStr['score']}")
                    self.text_widget.insert(END, "\n-------------------------------------------------\n")
                    
                self.text_widget.configure(state='disabled')

    def settings(self):
        self.settings = Toplevel()
        self.settings.title("Presidio Analyzer gRPC - Settings")
        self.settings.geometry("790x430")
        self.settings.configure(bg="#0B0C10")
        self.settings.resizable(0, 0)

        ## List of options
        frameList = Frame(self.settings, width = 100, height = 30)
        frameList.pack(side=LEFT, padx=8, pady=10)
    
        listbox_widget = Listbox(frameList, height = 20, font=("Courier", 12), bg="#1F2833", fg="#C5C6C7")

        ## Container options 
        self.frameOptions = Frame(self.settings, bg="#0B0C10")
        self.frameOptions.pack(side=RIGHT, pady = 15, padx = 10, expand = True)
        
        listbox_widget.insert(0, "Server settings")
        listbox_widget.insert(1, "PII Recognition")
        listbox_widget.insert(2, "Analyzer Options")

        listbox_widget.bind('<<ListboxSelect>>', self.clickEventOption)
        listbox_widget.pack()

    def clickEventOption(self, e):
        currSelection = e.widget.curselection()
        optionName = e.widget.get(currSelection)

        for widget in self.frameOptions.winfo_children():
            widget.destroy()

        if optionName == "Server settings":
            Label(self.frameOptions, text = "SERVER IP: " + IP_ADDRESS + " | SERVER PORT: " + str(PORT), font=("courier", 10), bg="#0B0C10", fg="#C5C6C7").pack(side=TOP)

            Label(self.frameOptions, text = "Server IP", font=("helvetica", 15), bg="#0B0C10", fg="#C5C6C7").pack(side=TOP, pady = 10)
            self.server_ip = Entry(self.frameOptions, font=("helvetica", 13), justify=CENTER, bd=3)
            self.server_ip.pack(anchor=S, pady = 5, padx = 20, ipady = 2)
            Label(self.frameOptions, text = "Server Port", font=("helvetica", 15), bg="#0B0C10", fg="#C5C6C7").pack(side=TOP, pady = 10)
            self.server_port = Entry(self.frameOptions, font=("helvetica", 13), justify=CENTER, bd=3)
            self.server_port.pack(anchor=S, pady = 5, padx = 20, ipady = 2)

            Button(self.frameOptions, text = "Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.setupServer).pack(side=TOP, ipadx = 10, pady = 10)
        
            if IP_ADDRESS != "null" and PORT != "null":
                self.server_ip.insert(0, IP_ADDRESS)
                self.server_port.insert(0, PORT)
        
        elif optionName == "Analyzer Options":
            
            frameNameOptions = Frame(self.frameOptions, width = 650, height = 60, bg="#0B0C10")
            frameNameOptions.grid(row = 0, column = 0, padx = 12)

            frameValues = Frame(self.frameOptions, width = 650, height = 60, bg="#0B0C10")
            frameValues.grid(row = 0, column = 1)

            Label(frameNameOptions, text = "LANGUAGE", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 0, column = 0, pady = 5)
            self.language =  Entry(frameValues, font=("helvetica", 13), bd=3)
            self.language.grid(row = 0, column = 0, pady = 5)
            
            Label(frameNameOptions, text = "ENTITIES", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 1, column = 0, pady = 5)
            self.entities =  Entry(frameValues, font=("helvetica", 13), bd=3)
            self.entities.grid(row = 1, column = 0, pady = 5)
            
            Label(frameNameOptions, text = "CORRELATION ID", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 2, column = 0, pady = 5)
            self.corr_id =  Entry(frameValues, font=("helvetica", 13), bd=3)
            self.corr_id.grid(row = 2, column = 0, pady = 5)

            Label(frameNameOptions, text = "SCORE THRESHOLD", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 3, column = 0, pady = 5)
            self.score =  Entry(frameValues, font=("helvetica", 13), bd=3)
            self.score.grid(row = 3, column = 0, pady = 5)

            self.decision_process = IntVar(None, int(ANALYZE_CURR_OPTIONS['return_decision_process']))

            Label(frameNameOptions, text = "RETURN DECISION PROCESS", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 4, column = 0, pady = 5)
            Radiobutton(frameValues, text="YES", font=("helvetica", 10), variable=self.decision_process, value=1).grid(row=4, sticky=W, pady = 5)
            Radiobutton(frameValues, text="NO", font=("helvetica", 10), variable=self.decision_process, value=0).grid(row=4, sticky=E, pady = 5)

            Button(self.frameOptions, text = "Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.saveAnalyzeConfig).grid(row = 5, columnspan = 2, ipadx = 10, pady = 20)

            # load the current config
            self.language.insert(0, ANALYZE_CURR_OPTIONS['language'])
            
            if ANALYZE_CURR_OPTIONS['entities'] != None:
                self.entities.insert(0, ANALYZE_CURR_OPTIONS['entities'])
            
            if ANALYZE_CURR_OPTIONS['correlation_id'] != None:
                self.corr_id.insert(0, ANALYZE_CURR_OPTIONS['correlation_id'])
            
            self.score.insert(0, ANALYZE_CURR_OPTIONS['score_threshold'])


        elif optionName == "PII Recognition":
            
            frameMenu = Frame(self.frameOptions, bg="#0B0C10")
            frameMenu.grid(row = 0, column = 0, padx = 12)

            self.frameInsertOption = Frame(self.frameOptions, width = 300, height = 150, bg="#0B0C10")
            self.frameInsertOption.grid(row = 0, column = 1, padx = 12)

            # menu options
            self.value_inside = StringVar()
  
            # Set the default value of the variable
            self.value_inside.set("Select an option")

            recognition_menu = OptionMenu(frameMenu, self.value_inside, "Select an option", *("Regex", "Deny List"), command=self.optionChanged)
            recognition_menu.pack()

            self.frameCurr = Frame(self.frameOptions, width = 520, height = 100, bg="#0B0C10")
            self.frameCurr.grid(row = 1, columnspan = 2, pady = 7)

    def setupServer(self):
        global IP_ADDRESS, PORT

        IP_ADDRESS = self.server_ip.get()
        PORT = self.server_port.get()

        messagebox.showinfo(parent=self.settings, title = "Save", message=f"Server options saved succefully!")
    
    def saveAnalyzeConfig(self):

        if self.language.get() != "en":
            messagebox.showerror("Setup Error", "Only English language is supported!")
        else:
            ANALYZE_CURR_OPTIONS['language'] = self.language.get()

        if self.entities.get() == "" or str(self.entities.get()).lower() == "none":
            ANALYZE_CURR_OPTIONS['entities'] = None
        else:
            ANALYZE_CURR_OPTIONS['entities'] = self.entities.get()
        
        if self.corr_id.get() == "":
            ANALYZE_CURR_OPTIONS['correlation_id'] = None
        else:
            ANALYZE_CURR_OPTIONS['correlation_id'] = self.corr_id.get()


        ANALYZE_CURR_OPTIONS['score_threshold'] = self.score.get()
        ANALYZE_CURR_OPTIONS['return_decision_process'] = str(self.decision_process.get())

        print(ANALYZE_CURR_OPTIONS)

        messagebox.showinfo(parent=self.settings, title = "Save", message=f"Options saved succefully!")

    def optionChanged(self, e):

        for widget in self.frameInsertOption.winfo_children():
            widget.destroy()
        
        for widget in self.frameCurr.winfo_children():
            widget.destroy()

        if self.value_inside.get() == "Deny List":
            Label(self.frameInsertOption, text = "ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 0, column = 0, pady = 5, padx = 5)
            self.entity = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.entity.grid(row = 0, column = 1, pady = 5)

            Label(self.frameInsertOption, text = "VALUES LIST", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 1, column = 0, pady = 5, padx = 5)
            self.values = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.values.grid(row = 1, column = 1, pady = 5)

            Button(self.frameInsertOption, text = "Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.setupDenyList).grid(row=3, column = 0, ipadx = 10, pady = 20)
            Button(self.frameInsertOption, text = "Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.clearDenyConfig).grid(row=3, column = 1, ipadx = 10, pady = 20)
        
            # Print current deny lists
            self.deny_widget = Text(self.frameCurr, font=("helvetica", 13), width = 60, height = 10, spacing1=3, bg="#1F2833", fg="#C5C6C7")
            self.deny_widget.grid(row = 0, column = 0)

            for i in range(DENY_LIST['length']):
                self.deny_widget.insert(END, f"{DENY_LIST['supported_entities'][i]} - {DENY_LIST['valuesList'][i]}\n")

            self.deny_widget.configure(state='disabled')

        elif self.value_inside.get() == "Regex":

            Label(self.frameInsertOption, text = "ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 0, column = 0, pady = 5, padx = 5)
            self.entity_regex = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.entity_regex.grid(row = 0, column = 1, pady = 5)

            Label(self.frameInsertOption, text = "NAME PATTERN", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 1, column = 0, pady = 5, padx = 5)
            self.name_pattern = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.name_pattern.grid(row = 1, column = 1, pady = 5)

            Label(self.frameInsertOption, text = "REGEX", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 2, column = 0, pady = 5, padx = 5)
            self.regex = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.regex.grid(row = 2, column = 1, pady = 5)

            Label(self.frameInsertOption, text = "SCORE", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 3, column = 0, pady = 5, padx = 5)
            self.score_regex = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.score_regex.grid(row = 3, column = 1, pady = 5)

            Label(self.frameInsertOption, text = "CONTEXT WORD", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 4, column = 0, pady = 5, padx = 5)
            self.context = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.context.grid(row = 4, column = 1, pady = 5)

            Button(self.frameInsertOption, text = "Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.setupRegexList).grid(row=5, column = 0, ipadx = 10, pady = 10)
            Button(self.frameInsertOption, text = "Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.clearRegexConfig).grid(row=5, column = 1, ipadx = 10, pady = 10)

            self.regex_widget = Text(self.frameCurr, font=("helvetica", 13), width = 60, height = 6, spacing1=3, bg="#1F2833", fg="#C5C6C7")
            self.regex_widget.grid(row = 0, column = 0)

            # print current regex patterns
            for i in range(REGEX_LIST['length']):
                self.regex_widget.insert(END, f"{REGEX_LIST['entities'][i]} - {REGEX_LIST['names_pattern'][i]} - {REGEX_LIST['patterns'][i]} - {REGEX_LIST['scores'][i]} - {REGEX_LIST['context_words'][i]}\n")

            self.regex_widget.configure(state='disabled')

    def setupDenyList(self):
        if len(self.entity.get()) > 2 and len(self.values.get()) > 2:
            DENY_LIST['supported_entities'].append(self.entity.get())
            DENY_LIST['valuesList'].append(self.values.get())
            DENY_LIST['length'] += 1
            self.deny_widget.configure(state='normal')
            self.deny_widget.insert(END, f"{self.entity.get()} - {self.values.get()}\n")
            self.deny_widget.configure(state='disabled')
            messagebox.showinfo(parent=self.settings, title = "Save", message=f"Deny list for {self.entity.get()} saved!")
        else:
            messagebox.showerror(parent=self.settings, title ="Error", message="Compile all the fields!")

        #print(DENY_LIST)

    def clearDenyConfig(self):
        answer = messagebox.askyesno(parent=self.settings, title = None, message="Do you want to reset deny list configuration?")
        
        if answer:
            DENY_LIST['supported_entities'] = []
            DENY_LIST['valuesList'] = []
            DENY_LIST['length'] = 0

            self.deny_widget.configure(state='normal')
            self.deny_widget.delete("1.0", END)
            self.deny_widget.configure(state='disabled')

    def setupRegexList(self):
        if len(self.entity_regex.get()) > 2:
            REGEX_LIST['entities'].append(self.entity_regex.get())
            REGEX_LIST['names_pattern'].append(self.name_pattern.get())
            REGEX_LIST['patterns'].append(self.regex.get())
            REGEX_LIST['scores'].append(self.score_regex.get())
            REGEX_LIST['context_words'].append(self.context.get())
            REGEX_LIST['length'] += 1
            self.regex_widget.configure(state='normal')
            self.regex_widget.insert(END, f"{self.entity_regex.get()} - {self.name_pattern.get()} - {self.regex.get()} - {self.score_regex.get()} - {self.context.get()}\n")
            self.regex_widget.configure(state='disabled')
            messagebox.showinfo(parent=self.settings, title = "Save", message=f"Regex for {self.entity_regex.get()} saved!")
        else:
            messagebox.showerror(parent=self.settings, title ="Error", message="Compile all the fields!")

        #print(REGEX_LIST)
    
    def clearRegexConfig(self):
        answer = messagebox.askyesno(parent=self.settings, title = None, message="Do you want to reset regex configuration?")
        
        if answer:
            REGEX_LIST['entities'] = []
            REGEX_LIST['names_pattern'] = []
            REGEX_LIST['patterns'] = []
            REGEX_LIST['scores'] = []
            REGEX_LIST['context_words'] = []
            REGEX_LIST['length'] = 0

            self.regex_widget.configure(state='normal')
            self.regex_widget.delete("1.0", END)
            self.regex_widget.configure(state='disabled')

root = Tk()
app = Frames(root)
root.mainloop()