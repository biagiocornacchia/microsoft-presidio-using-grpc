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

            # send config

            filenameList = []
            for path in self.root.filenames:
                filename, ext = os.path.basename(path).split(".")
                filenameList.append(filename)

                res = clientAnoymizer.sendRequestDeanonymize(os.path.basename(filename))
                
                if res == -2:
                    messagebox.showerror("gRPC Server Error", "Cannot connect to the server! Check your server settings")
                    break
                elif res == -1:
                    messagebox.showerror("gRPC Server Error", "ERROR: anonymized file text or anonymizer items not found!")
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
        pass

root = Tk()
app = Frames(root)
root.mainloop()