import anonymizer_client as anonymizer

from tkinter import *
from tkinter import filedialog
from tkinter import messagebox

import json

import os
from pathlib import Path

IP_ADDRESS = "localhost"
PORT = "8061"


class Frames(object):

    def __init__(self, root):
        self.root = root
        self.root.title('Presidio Anonymizer gRPC Client')
        self.root.geometry('650x260')
        self.root.configure(bg="#0B0C10")
        self.root.resizable(0, 0)        

        # Title
        frameTitle = Frame(self.root, width = 650, height = 60, bg="#0B0C10")
        frameTitle.grid(row = 0, columnspan = 2)

        Label(frameTitle, text="Microsoft Presidio Anonymizer", font=("Helvetica", 17, "bold"), bg="#0B0C10", fg="#C5C6C7", anchor = CENTER).pack(ipady = 20)

        # Anonymizer & Deanonymizer buttons
        frameBtnAnonymize = Frame(self.root, width = 650, height = 1, bg="#0B0C10")
        frameBtnAnonymize.grid(row = 1, columnspan = 2)

        anonymizeBtn = Button(frameTitle, text="Anonymizer", font=("Helvetica", 14), bg="#0B0C10", fg="#C5C6C7", command = self.startAnonymizer).pack(pady = 22, ipadx= 17, ipady = 3, side=LEFT)
        deanonymizeBtn = Button(frameTitle, text="Deanonymizer", font=("Helvetica", 14), bg="#0B0C10", fg="#C5C6C7", command = self.startDeanonymizer).pack(pady = 22, ipadx= 8, ipady = 3, side=RIGHT)

        # Settings
        frameBtnSettings = Frame(self.root, bg="#0B0C10")
        frameBtnSettings.grid(row = 2, columnspan = 2)

        settingsButton = Button(frameBtnSettings, text="Settings", font=("Helvetica", 14), bg="#0B0C10", fg="#C5C6C7", command = self.settings).pack(pady = 10, ipadx= 33, ipady = 3)
    
    def startAnonymizer(self):

        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = Path(dir_path)

        self.root.filenames = filedialog.askopenfilenames(initialdir= str(path.parent.absolute()) + "/files", title="Select A File", filetypes=(("txt files", "*.txt"),("all files", "*.*")))
        
        if self.root.filenames:

            clientAnoymizer = anonymizer.ClientEntity(IP_ADDRESS, PORT)

            # send options if setted

            filenameList = []
            for path in self.root.filenames:
                filename, ext = os.path.basename(path).split(".")
                filenameList.append(filename)

                res = clientAnoymizer.sendRequestAnonymize(os.path.basename(filename))
                
                if res == -2:
                    messagebox.showerror("gRPC Server Error", "Cannot connect to the server! Check your server settings")
                    break
                elif res == -1:
                    messagebox.showerror("gRPC Server Error", "ERROR: original file text or analyzer results not found!")
                    break                

            if res == 1:
                clientAnoymizer.closeConnection()
                self.readAnonymizerResults(filenameList)

    def startDeanonymizer(self):
        
        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = Path(dir_path)

        self.root.filenames = filedialog.askopenfilenames(initialdir= str(path.parent.absolute()) + "/anonymizer-results", title="Select A File", filetypes=(("txt files", "*.txt"),("all files", "*.*")))
        
        if self.root.filenames:

            clientAnoymizer = anonymizer.ClientEntity(IP_ADDRESS, PORT)

            filenameList = []
            for path in self.root.filenames:
                filename, ext = os.path.basename(path).split(".")
                filenameList.append(filename)

                res = clientAnoymizer.sendRequestDeanonymize(os.path.basename(filename))
                
                if res == -2:
                    messagebox.showerror("gRPC Server Error", "Cannot connect to the server! Check your server settings")
                    break
                elif res == -1:
                    messagebox.showerror("gRPC Server Error", "ERROR: configuration file, anonymized file text or anonymizer items not found!")
                    break                

            if res == 1:
                clientAnoymizer.closeConnection()
                self.readDeanonymizerResults(filenameList)

    def readAnonymizerResults(self, filenameList):
        self.result = Toplevel()
        self.result.title("Presidio Anonymizer gRPC - RESULTS")
        self.result.geometry("1200x600")
        self.result.configure(bg="#0B0C10")
        #self.result.resizable(0, 0)

        ## List filename-results.txt
        frameList = Frame(self.result, height = 30)
        frameList.pack(side=LEFT, padx=13)

        # Scrollbar
        resultsScrollbar = Scrollbar(frameList, orient=VERTICAL)

        listbox_widget = Listbox(frameList, yscrollcommand=resultsScrollbar.set, width=26, height = 20, font=("Courier", 12), bg="#1F2833", fg="#C5C6C7")
        
        # configure scrollbar
        resultsScrollbar.config(command=listbox_widget.yview)
        resultsScrollbar.pack(side=RIGHT, fill=Y)
        ## END LIST

        ## Frame that will contain results
        frameResults = Frame(self.result, bg="#0B0C10")
        frameResults.pack(side=RIGHT, pady = 15, padx = 10)
        
        self.text_widget = Text(frameResults, font=("Courier", 13), spacing1=3, width = 1300, bg="#1F2833", fg="#C5C6C7")
        self.text_widget.pack(pady = 10, padx= 4)
        ## END FRAME
        
        for filename in filenameList:
            listbox_widget.insert(END, filename + "-anonymized")
            listbox_widget.insert(END, filename + "-anonymized-items")

        listbox_widget.bind('<<ListboxSelect>>', self.resultClickEvent)
        listbox_widget.pack()

    def resultClickEvent(self, e):
	
        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = Path(dir_path)

        currSelection = e.widget.curselection()
        filename = e.widget.get(currSelection)


        with open(str(path.parent.absolute()) + "/anonymizer-results/" + filename + ".txt", "r") as resultsFile:

            self.text_widget.configure(state='normal')
            self.text_widget.delete("1.0", END)

            if "anonymized-item" in filename:
                for line in resultsFile:
                    resultStr = json.loads(line)
                    self.text_widget.insert(END, f"ENTITY TYPE: {resultStr['entity_type']}\nOPERATOR: {resultStr['operator']}\nTEXT: {resultStr['text']}\nSTART: {resultStr['start']}\nEND: {resultStr['end']}")
                    self.text_widget.insert(END, "\n-------------------------------------------------------------\n")
            else:
                self.text_widget.delete("1.0", END)                   
                self.text_widget.insert(END, resultsFile.read())
                
            self.text_widget.configure(state='disabled')

    def readDeanonymizerResults(self, filenameList):
        self.result = Toplevel()
        self.result.title("Presidio Anonymizer gRPC - RESULTS")
        self.result.geometry("1200x600")
        self.result.configure(bg="#0B0C10")
        #self.result.resizable(0, 0)

        ## List filename-results.txt
        frameList = Frame(self.result, height = 30)
        frameList.pack(side=LEFT, padx=13)

        # Scrollbar
        resultsScrollbar = Scrollbar(frameList, orient=VERTICAL)

        listbox_widget = Listbox(frameList, yscrollcommand=resultsScrollbar.set, width=26, height = 20, font=("Courier", 12), bg="#1F2833", fg="#C5C6C7")
        
        # configure scrollbar
        resultsScrollbar.config(command=listbox_widget.yview)
        resultsScrollbar.pack(side=RIGHT, fill=Y)
        ## END LIST

        ## Frame that will contain results
        frameResults = Frame(self.result, bg="#0B0C10")
        frameResults.pack(side=RIGHT, pady = 15, padx = 10)
        
        self.text_widget = Text(frameResults, font=("Courier", 13), spacing1=3, width = 1300, bg="#1F2833", fg="#C5C6C7")
        self.text_widget.pack(pady = 10, padx = 4)
        ## END FRAME
        
        for filename in filenameList:
            filename = filename.split("-")[0]
            listbox_widget.insert(END, filename + "-deanonymized")
            listbox_widget.insert(END, filename + "-deanonymized-items")

        listbox_widget.bind('<<ListboxSelect>>', self.resultClickEvent)
        listbox_widget.pack()

    def settings(self):
        self.settings = Toplevel()
        self.settings.title("Presidio Anonymizer gRPC - Settings")
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
        listbox_widget.insert(1, "Anonymizer Config")
        listbox_widget.insert(2, "Deanonymizer Config")

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
        
        elif optionName == "Anonymizer Config":
            
            frameMenu = Frame(self.frameOptions, bg="#0B0C10")
            frameMenu.grid(row = 0, column = 0, padx = 12)

            self.frameInsertOption = Frame(self.frameOptions, width = 300, height = 150, bg="#0B0C10")
            self.frameInsertOption.grid(row = 0, column = 1, padx = 12)

            # menu options
            self.value_inside = StringVar()
  
            # Set the default value of the variable
            self.value_inside.set("Select an option")

            operator = OptionMenu(frameMenu, self.value_inside, "Select an option", *("Replace", "Redact", "Mask", "Encrypt", "Hash"), command=self.optionChanged)
            operator.pack()

            self.frameCurr = Frame(self.frameOptions, width = 520, height = 100, bg="#0B0C10")
            self.frameCurr.grid(row = 1, columnspan = 2, pady = 7)

            self.anonymizer_options = Text(self.frameCurr, font=("helvetica", 13), width = 60, height = 7, spacing1=3, bg="#1F2833", fg="#C5C6C7")
            self.anonymizer_options.grid(row = 0, column = 0)

            dir_path = os.path.dirname(os.path.realpath(__file__))
            path = Path(dir_path)

            if os.path.exists(str(path) + "/config/operatorConfigAnonymizer.txt"):
                with open(str(path) + "/config/operatorConfigAnonymizer.txt", "r") as fileConfig:
                    for line in fileConfig:
                        options = json.loads(line)
                        self.anonymizer_options.insert(END, f"ENTITY: {options['entity_type']} : {json.loads(options['params'])} \n")

                self.anonymizer_options.configure(state='disabled')
            
        elif optionName == "Deanonymizer Config":
            
            frameMenu = Frame(self.frameOptions, bg="#0B0C10")
            frameMenu.grid(row = 0, column = 0, padx = 12)

            self.frameInsertOption = Frame(self.frameOptions, width = 300, height = 150, bg="#0B0C10")
            self.frameInsertOption.grid(row = 0, column = 1, padx = 12)

            # menu options
            self.value_inside = StringVar()
  
            # Set the default value of the variable
            self.value_inside.set("Select an option")

            operator = OptionMenu(frameMenu, self.value_inside, "Select an option", ("Decrypt"), command=self.optionChanged)
            operator.pack()

            self.frameCurr = Frame(self.frameOptions, width = 520, height = 100, bg="#0B0C10")
            self.frameCurr.grid(row = 1, columnspan = 2, pady = 7)

            self.deanonymizer_options = Text(self.frameCurr, font=("helvetica", 13), width = 60, height = 7, spacing1=3, bg="#1F2833", fg="#C5C6C7")
            self.deanonymizer_options.grid(row = 0, column = 0)

            dir_path = os.path.dirname(os.path.realpath(__file__))
            path = Path(dir_path)

            if os.path.exists(str(path) + "/config/operatorConfigDeanonymizer.txt"):
                with open(str(path) + "/config/operatorConfigDeanonymizer.txt", "r") as fileConfig:
                    for line in fileConfig:
                        options = json.loads(line)
                        self.deanonymizer_options.insert(END, f"ENTITY: {options['entity_type']} : {json.loads(options['params'])} \n")

                self.deanonymizer_options.configure(state='disabled')

    def optionChanged(self, e):

        for widget in self.frameInsertOption.winfo_children():
            widget.destroy()

        if self.value_inside.get() == "Replace":
            Label(self.frameInsertOption, text = "ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 0, column = 0, pady = 5, padx = 5)
            self.entity = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.entity.grid(row = 0, column = 1, pady = 5)

            Label(self.frameInsertOption, text = "NEW VALUE", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 1, column = 0, pady = 5, padx = 5)
            self.new_value = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.new_value.grid(row = 1, column = 1, pady = 5)

            Button(self.frameInsertOption, text = "Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.setupOperator).grid(row=3, column = 0, ipadx = 10, pady = 20)
            Button(self.frameInsertOption, text = "Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.clearAnonymizerConfig).grid(row=3, column = 1, ipadx = 10, pady = 20)
        
        elif self.value_inside.get() == "Redact":

            Label(self.frameInsertOption, text = "ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 0, column = 0, pady = 5, padx = 5)
            self.entity = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.entity.grid(row = 0, column = 1, pady = 5)

            Button(self.frameInsertOption, text = "Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.setupOperator).grid(row=1, column = 0, ipadx = 10, pady = 20)
            Button(self.frameInsertOption, text = "Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.clearAnonymizerConfig).grid(row=1, column = 1, ipadx = 10, pady = 20)

        elif self.value_inside.get() == "Mask":

            Label(self.frameInsertOption, text = "ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 0, column = 0, pady = 5, padx = 5)
            self.entity = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.entity.grid(row = 0, column = 1, pady = 5)

            Label(self.frameInsertOption, text = "MASKING CHAR", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 1, column = 0, pady = 5, padx = 5)
            self.masking_char = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.masking_char.grid(row = 1, column = 1, pady = 5)

            Label(self.frameInsertOption, text = "CHARS TO MASK", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 2, column = 0, pady = 5, padx = 5)
            self.chars_to_mask = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.chars_to_mask.grid(row = 2, column = 1, pady = 5)

            Label(self.frameInsertOption, text = "FROM END", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 3, column = 0, pady = 5, padx = 5)
            self.from_end = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.from_end.grid(row = 3, column = 1, pady = 5)

            Button(self.frameInsertOption, text = "Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.setupOperator).grid(row=4, column = 0, ipadx = 10, pady = 20)
            Button(self.frameInsertOption, text = "Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.clearAnonymizerConfig).grid(row=4, column = 1, ipadx = 10, pady = 20)
        
        elif self.value_inside.get() == "Encrypt":

            Label(self.frameInsertOption, text = "ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 0, column = 0, pady = 5, padx = 5)
            self.entity = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.entity.grid(row = 0, column = 1, pady = 5)

            Label(self.frameInsertOption, text = "KEY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 1, column = 0, pady = 5, padx = 5)
            self.key = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.key.grid(row = 1, column = 1, pady = 5)

            Button(self.frameInsertOption, text = "Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.setupOperator).grid(row=3, column = 0, ipadx = 10, pady = 20)
            Button(self.frameInsertOption, text = "Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.clearAnonymizerConfig).grid(row=3, column = 1, ipadx = 10, pady = 20)
        
        elif self.value_inside.get() == "Hash":
            Label(self.frameInsertOption, text = "ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 0, column = 0, pady = 5, padx = 5)
            self.entity = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.entity.grid(row = 0, column = 1, pady = 5)

            Label(self.frameInsertOption, text = "HASH TYPE", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 1, column = 0, pady = 5, padx = 5)
            self.hash_type = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.hash_type.grid(row = 1, column = 1, pady = 5)

            Button(self.frameInsertOption, text = "Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.setupOperator).grid(row=3, column = 0, ipadx = 10, pady = 20)
            Button(self.frameInsertOption, text = "Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.clearAnonymizerConfig).grid(row=3, column = 1, ipadx = 10, pady = 20)

        elif self.value_inside.get() == "Decrypt":

            Label(self.frameInsertOption, text = "ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 0, column = 0, pady = 5, padx = 5)
            self.entity = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.entity.grid(row = 0, column = 1, pady = 5)

            Label(self.frameInsertOption, text = "KEY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7").grid(row = 1, column = 0, pady = 5, padx = 5)
            self.key = Entry(self.frameInsertOption, font=("helvetica", 13), bd=3)
            self.key.grid(row = 1, column = 1, pady = 5)

            Button(self.frameInsertOption, text = "Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.setupOperator).grid(row=3, column = 0, ipadx = 10, pady = 20)
            Button(self.frameInsertOption, text = "Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7", command=self.clearDeanonymizerConfig).grid(row=3, column = 1, ipadx = 10, pady = 20)
                
    def setupOperator(self):

        res = -1
        entity = str(self.entity.get()).upper()

        if len(entity) > 2:
            if self.value_inside.get() == "Hash":
                res = anonymizer.addHash(entity, self.hash_type.get())
            elif self.value_inside.get() == "Replace":
                res = anonymizer.addReplace(entity, self.new_value.get())
            elif self.value_inside.get() == "Redact":
                res = anonymizer.addRedact(entity)
            elif self.value_inside.get() == "Mask":
                res = anonymizer.addMask(entity, self.masking_char.get(), self.chars_to_mask.get(), self.from_end.get())
            elif self.value_inside.get() == "Encrypt":
                res = anonymizer.addEncrypt(entity, self.key.get())
            elif self.value_inside.get() == "Decrypt":
                res = anonymizer.addDecrypt(entity, self.key.get())

            if res == 1:
                messagebox.showinfo(parent=self.settings, title = "Update", message=f"Option for {entity} updated!")
            elif res == 0:
                # saved
                messagebox.showinfo(parent=self.settings, title = "Save", message=f"Option for {entity} saved!")
        else:
            messagebox.showerror(parent=self.settings, title = "Error configuration", message=f"You have to fill in all the fields!")

    def clearAnonymizerConfig(self):

        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = Path(dir_path)

        answer = messagebox.askyesno(parent=self.settings, title = None, message="Do you want to reset configuration file?")
        
        if answer and os.path.exists(str(path) + "/config/operatorConfigAnonymizer.txt"):

            os.remove(str(path) + "/config/operatorConfigAnonymizer.txt")

            self.anonymizer_options.configure(state='normal')
            self.anonymizer_options.delete("1.0", END)
            self.anonymizer_options.configure(state='disabled')

    def clearDeanonymizerConfig(self):

        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = Path(dir_path)

        answer = messagebox.askyesno(parent=self.settings, title = None, message="Do you want to reset configuration file?")
        
        if answer and os.path.exists(str(path) + "/config/operatorConfigDeanonymizer.txt"):

            os.remove(str(path) + "/config/operatorConfigDeanonymizer.txt")

            self.deanonymizer_options.configure(state='normal')
            self.deanonymizer_options.delete("1.0", END)
            self.deanonymizer_options.configure(state='disabled')

    def setupServer(self):
        global IP_ADDRESS, PORT

        IP_ADDRESS = self.server_ip.get()
        PORT = self.server_port.get()

        messagebox.showinfo(parent=self.settings, title = "Save", message=f"Server options saved succefully!")

root = Tk()
app = Frames(root)
root.mainloop()