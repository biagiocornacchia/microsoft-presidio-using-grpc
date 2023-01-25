import analyzer_client as analyzer

from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk

import json
import os
from pathlib import Path

IP_ADDRESS = 'localhost'
PORT = 8061


class Frames(object):
    def __init__(self, root):
        self.engine_current_options = {}
        self.analyze_current_options = {
            'language': 'en',
            'entities': None,
            'correlation_id': None,
            'score_threshold': '0.1',
            'return_decision_process': '0'
        }
        self.deny_list = {
            'supported_entities': [],
            'values_list': [],
            'length': 0
        }
        self.regex_list = {
            'entities': [],
            'names_pattern': [],
            'patterns': [],
            'scores': [],
            'context_words': [],
            'length': 0
        }

        self.decision_process = None
        self.score = None
        self.correlation_id = None
        self.entities = None
        self.language = None
        self.server_port = None
        self.server_ip = None

        self.regex_widget = None
        self.context = None
        self.score_regex = None
        self.name_pattern = None
        self.regex = None
        self.entity_regex = None

        self.deny_widget = None
        self.values = None
        self.entity = None

        self.root = root
        self.root.title('Presidio Analyzer gRPC Client')
        self.root.geometry('650x260')
        self.root.configure(bg="#0B0C10")
        self.root.resizable(0, 0)

        # Title
        frame_title = Frame(self.root, width=650, height=60, bg="#0B0C10")
        frame_title.grid(row=0, columnspan=2)

        Label(frame_title, text="Microsoft Presidio Analyzer", font=("Helvetica", 17, "bold"), bg="#0B0C10",
              fg="#C5C6C7", anchor=CENTER).pack(ipady=20)

        # Settings
        frame_btn_settings = Frame(self.root, bg="#0B0C10")
        frame_btn_settings.grid(row=2, columnspan=2)

        Button(frame_btn_settings, text="Settings", font=("Helvetica", 14), bg="#0B0C10", fg="#C5C6C7",
               command=self.settings).pack(pady=10, ipadx=33, ipady=3)

        # Start analyzer
        frame_btn_analyze = Frame(self.root, width=650, height=1, bg="#0B0C10")
        frame_btn_analyze.grid(row=1, columnspan=2)

        Button(frame_title, text="Start analyzer", font=("Helvetica", 14), bg="#0B0C10", fg="#C5C6C7",
               command=self.start_analyzer).pack(pady=22, ipadx=10, ipady=3)

    def start_analyzer(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = Path(dir_path)

        self.root.filenames = filedialog.askopenfilenames(initialdir=str(path.parent.absolute()) + "/files",
                                                          title="Select A File",
                                                          filetypes=(("txt files", "*.txt"), ("all files", "*.*")))

        if self.root.filenames:
            client_analyzer = analyzer.ClientEntity(IP_ADDRESS, PORT)

            # Send options if set
            for elem in self.analyze_current_options:
                client_analyzer.setup_options(elem, self.analyze_current_options[elem], "ANALYZE_OPTIONS")

            if self.deny_list['length'] > 0:
                client_analyzer.setup_deny_list(self.deny_list['supported_entities'], self.deny_list['values_list'])

            if self.regex_list['length'] > 0:
                patterns = analyzer.create_pattern_info(1, self.regex_list['names_pattern'], self.regex_list['patterns'],
                                                        self.regex_list['scores'])
                client_analyzer.setup_regex(self.regex_list['entities'][0], patterns, self.regex_list['context_words'][0])

            progress_window = Toplevel()
            progress_window.title("Analyzer Status")
            progress_window.geometry("330x80")
            progress_window.configure(bg="white")
            self.root.update_idletasks()

            Label(progress_window, text="Analyzer process is starting..it may take a while!", font=("Helvetica", 10),
                  bg="white", fg="black").pack(side=TOP, padx=15, pady=7)
            progress_bar = ttk.Progressbar(progress_window, orient=HORIZONTAL, length=200, mode="determinate")
            progress_bar.pack(side=TOP, pady=14)
            self.root.update_idletasks()

            filename_list = []
            for path in self.root.filenames:

                filename, ext = os.path.basename(path).split(".")
                filename_list.append(filename)

                res = client_analyzer.send_analyzer_request(os.path.basename(filename))

                if res == -2:
                    progress_window.destroy()
                    messagebox.showerror("gRPC Server Error",
                                         "Cannot connect to the server! Check your server settings")
                    break

                if progress_bar['value'] < 100:
                    progress_bar['value'] += (100 / len(self.root.filenames))
                    self.root.update_idletasks()

                if int(progress_bar['value']) == 100:
                    messagebox.showinfo(parent=progress_window, message='Analyzer process completed!')
                    progress_window.destroy()

            if res != -2:
                client_analyzer.close_connection()
                self.read_results(filename_list)

    def read_results(self, filename_list):
        self.result = Toplevel()
        self.result.title("Presidio Analyzer gRPC - RESULTS")
        self.result.geometry("850x450")
        self.result.configure(bg="#0B0C10")
        self.result.resizable(0, 0)

        # List filename-results.txt
        frame_list = Frame(self.result, width=150, height=30)
        frame_list.pack(side=LEFT, padx=13)

        # Scrollbar
        results_scrollbar = Scrollbar(frame_list, orient=VERTICAL)

        listbox_widget = Listbox(frame_list, yscrollcommand=results_scrollbar.set, height=20, font=("Courier", 12),
                                 bg="#1F2833", fg="#C5C6C7")

        # Configure scrollbar
        results_scrollbar.config(command=listbox_widget.yview)
        results_scrollbar.pack(side=RIGHT, fill=Y)
        # End list

        # Frame that will contain results
        frame_results = Frame(self.result, width=680, bg="#0B0C10")
        frame_results.pack(side=RIGHT, pady=15, padx=10)

        self.text_widget = Text(frame_results, font=("Courier", 13), spacing1=3, bg="#1F2833", fg="#C5C6C7")
        self.text_widget.pack(pady=10, padx=15)
        # End frame

        for filename in filename_list:
            listbox_widget.insert(END, filename)

        listbox_widget.bind('<<ListboxSelect>>', self.click_event)
        listbox_widget.pack()

    def click_event(self, e):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = Path(dir_path)

        curr_selection = e.widget.curselection()
        filename = e.widget.get(curr_selection)
        # print(filename)

        with open(os.path.join(os.path.abspath('..'), 'files', f'{filename}.txt'), 'r') as original_file:
            original_text = original_file.read()

            with open(os.path.join(os.path.abspath('..'), 'analyzer-results', f'{filename}-results.json'),
                      'r') as results_file:
                self.text_widget.configure(state='normal')
                self.text_widget.delete("1.0", END)
                analyzer_result = json.loads(results_file.read())

                for entity in analyzer_result['results']:
                    # print(entity)
                    start = entity['start']
                    end = entity['end']

                    self.text_widget.insert(END, f"FOUND WORD: {original_text[start:end]}\n\n")
                    self.text_widget.insert(END,
                                            f"ENTITY TYPE: {entity['entity_type']}\n"
                                            f"START: {entity['start']}\n"
                                            f"END: {entity['end']}\n"
                                            f"SCORE: {entity['score']}")
                    self.text_widget.insert(END, "\n-------------------------------------------------\n")
                self.text_widget.configure(state='disabled')

    def settings(self):
        self.settings = Toplevel()
        self.settings.title("Presidio Analyzer gRPC - Settings")
        self.settings.geometry("790x430")
        self.settings.configure(bg="#0B0C10")
        self.settings.resizable(0, 0)

        # List of options
        frame_list = Frame(self.settings, width=100, height=30)
        frame_list.pack(side=LEFT, padx=8, pady=10)

        listbox_widget = Listbox(frame_list, height=20, font=("Courier", 12), bg="#1F2833", fg="#C5C6C7")

        # Container options
        self.frameOptions = Frame(self.settings, bg="#0B0C10")
        self.frameOptions.pack(side=RIGHT, pady=15, padx=10, expand=True)

        listbox_widget.insert(0, "Server settings")
        listbox_widget.insert(1, "PII Recognition")
        listbox_widget.insert(2, "Analyzer Options")

        listbox_widget.bind('<<ListboxSelect>>', self.click_event_option)
        listbox_widget.pack()

    def click_event_option(self, e):
        curr_selection = e.widget.curselection()
        option_name = e.widget.get(curr_selection)

        for widget in self.frameOptions.winfo_children():
            widget.destroy()

        if option_name == "Server settings":
            Label(self.frameOptions, text="SERVER IP: " + IP_ADDRESS + " | SERVER PORT: " + str(PORT),
                  font=("courier", 10), bg="#0B0C10", fg="#C5C6C7").pack(side=TOP)

            Label(self.frameOptions, text="Server IP", font=("helvetica", 15), bg="#0B0C10", fg="#C5C6C7").pack(
                side=TOP, pady=10)
            self.server_ip = Entry(self.frameOptions, font=("helvetica", 13), justify=CENTER, bd=3)
            self.server_ip.pack(anchor=S, pady=5, padx=20, ipady=2)
            Label(self.frameOptions, text="Server Port", font=("helvetica", 15), bg="#0B0C10", fg="#C5C6C7").pack(
                side=TOP, pady=10)
            self.server_port = Entry(self.frameOptions, font=("helvetica", 13), justify=CENTER, bd=3)
            self.server_port.pack(anchor=S, pady=5, padx=20, ipady=2)

            Button(self.frameOptions, text="Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.setup_server).pack(side=TOP, ipadx=10, pady=10)

            if IP_ADDRESS != "null" and PORT != "null":
                self.server_ip.insert(0, IP_ADDRESS)
                self.server_port.insert(0, str(PORT))

        elif option_name == "Analyzer Options":
            frame_name_options = Frame(self.frameOptions, width=650, height=60, bg="#0B0C10")
            frame_name_options.grid(row=0, column=0, padx=12)

            frame_values = Frame(self.frameOptions, width=650, height=60, bg="#0B0C10")
            frame_values.grid(row=0, column=1)

            Label(frame_name_options, text="LANGUAGE", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7") \
                .grid(row=0, column=0, pady=5)
            self.language = Entry(frame_values, font=("helvetica", 13), bd=3)
            self.language.grid(row=0, column=0, pady=5)

            Label(frame_name_options, text="ENTITIES", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7") \
                .grid(row=1, column=0, pady=5)
            self.entities = Entry(frame_values, font=("helvetica", 13), bd=3)
            self.entities.grid(row=1, column=0, pady=5)

            Label(frame_name_options, text="CORRELATION ID", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7") \
                .grid(row=2, column=0, pady=5)
            self.correlation_id = Entry(frame_values, font=("helvetica", 13), bd=3)
            self.correlation_id.grid(row=2, column=0, pady=5)

            Label(frame_name_options, text="SCORE THRESHOLD", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7") \
                .grid(row=3, column=0, pady=5)
            self.score = Entry(frame_values, font=("helvetica", 13), bd=3)
            self.score.grid(row=3, column=0, pady=5)

            self.decision_process = IntVar(None, int(self.analyze_current_options['return_decision_process']))

            Label(frame_name_options, text="RETURN DECISION PROCESS", font=("helvetica", 13), bg="#0B0C10",
                  fg="#C5C6C7") \
                .grid(row=4, column=0, pady=5)
            Radiobutton(frame_values, text="YES", font=("helvetica", 10), variable=self.decision_process, value=1) \
                .grid(row=4, sticky=W, pady=5)
            Radiobutton(frame_values, text="NO", font=("helvetica", 10), variable=self.decision_process, value=0) \
                .grid(row=4, sticky=E, pady=5)

            Button(self.frameOptions, text="Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.save_analyze_config).grid(row=5, columnspan=2, ipadx=10, pady=20)

            # Load the current configuration
            self.language.insert(0, self.analyze_current_options['language'])

            if self.analyze_current_options['entities'] is not None:
                self.entities.insert(0, self.analyze_current_options['entities'])

            if self.analyze_current_options['correlation_id'] is not None:
                self.correlation_id.insert(0, self.analyze_current_options['correlation_id'])

            self.score.insert(0, self.analyze_current_options['score_threshold'])
        elif option_name == "PII Recognition":
            frame_menu = Frame(self.frameOptions, bg="#0B0C10")
            frame_menu.grid(row=0, column=0, padx=12)

            self.frame_insert_option = Frame(self.frameOptions, width=300, height=150, bg="#0B0C10")
            self.frame_insert_option.grid(row=0, column=1, padx=12)

            # Menu options
            self.value_inside = StringVar()

            # Set the default value of the variable
            self.value_inside.set("Select an option")

            recognition_menu = OptionMenu(frame_menu, self.value_inside, "Select an option", *("Regex", "Deny List"),
                                          command=self.change_option)
            recognition_menu.pack()

            self.frame_curr = Frame(self.frameOptions, width=520, height=100, bg="#0B0C10")
            self.frame_curr.grid(row=1, columnspan=2, pady=7)

    def setup_server(self):
        global IP_ADDRESS, PORT

        IP_ADDRESS = self.server_ip.get()
        PORT = self.server_port.get()

        messagebox.showinfo(parent=self.settings, title="Save", message=f"Server options saved successfully!")

    def save_analyze_config(self):
        if self.language.get() != "en":
            messagebox.showerror("Setup Error", "Only English language is supported!")
        else:
            self.analyze_current_options['language'] = self.language.get()

        if self.entities.get() == "" or str(self.entities.get()).lower() == "none":
            self.analyze_current_options['entities'] = None
        else:
            self.analyze_current_options['entities'] = self.entities.get()

        if self.correlation_id.get() == "":
            self.analyze_current_options['correlation_id'] = None
        else:
            self.analyze_current_options['correlation_id'] = self.correlation_id.get()

        self.analyze_current_options['score_threshold'] = self.score.get()
        self.analyze_current_options['return_decision_process'] = str(self.decision_process.get())

        print(self.analyze_current_options)

        messagebox.showinfo(parent=self.settings, title="Save", message=f"Options saved successfully!")

    def change_option(self, e):
        for widget in self.frame_insert_option.winfo_children():
            widget.destroy()

        for widget in self.frame_curr.winfo_children():
            widget.destroy()

        if self.value_inside.get() == "Deny List":
            Label(self.frame_insert_option, text="ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7") \
                .grid(row=0, pady=5, padx=5)
            self.entity = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.entity.grid(row=0, column=1, pady=5)

            Label(self.frame_insert_option, text="VALUES LIST", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7") \
                .grid(row=1, column=0, pady=5, padx=5)
            self.values = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.values.grid(row=1, column=1, pady=5)

            Button(self.frame_insert_option, text="Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.setup_deny_list).grid(row=3, column=0, ipadx=10, pady=20)
            Button(self.frame_insert_option, text="Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.clear_deny_config).grid(row=3, column=1, ipadx=10, pady=20)

            # Print current deny lists
            self.deny_widget = Text(self.frame_curr, font=("helvetica", 13), width=60, height=10, spacing1=3,
                                    bg="#1F2833", fg="#C5C6C7")
            self.deny_widget.grid(row=0, column=0)

            for i in range(self.deny_list['length']):
                self.deny_widget.insert(END, f"{self.deny_list['supported_entities'][i]} - {self.deny_list['values_list'][i]}\n")

            self.deny_widget.configure(state='disabled')
        elif self.value_inside.get() == "Regex":
            Label(self.frame_insert_option, text="ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7") \
                .grid(row=0, column=0, pady=5, padx=5)
            self.entity_regex = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.entity_regex.grid(row=0, column=1, pady=5)

            Label(self.frame_insert_option, text="NAME PATTERN", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7") \
                .grid(row=1, column=0, pady=5, padx=5)
            self.name_pattern = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.name_pattern.grid(row=1, column=1, pady=5)

            Label(self.frame_insert_option, text="REGEX", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7") \
                .grid(row=2, column=0, pady=5, padx=5)
            self.regex = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.regex.grid(row=2, column=1, pady=5)

            Label(self.frame_insert_option, text="SCORE", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7") \
                .grid(row=3, column=0, pady=5, padx=5)
            self.score_regex = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.score_regex.grid(row=3, column=1, pady=5)

            Label(self.frame_insert_option, text="CONTEXT WORD", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7") \
                .grid(row=4, column=0, pady=5, padx=5)
            self.context = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.context.grid(row=4, column=1, pady=5)

            Button(self.frame_insert_option, text="Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.setup_regex_list).grid(row=5, column=0, ipadx=10, pady=10)
            Button(self.frame_insert_option, text="Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.clear_regex_config).grid(row=5, column=1, ipadx=10, pady=10)

            self.regex_widget = Text(self.frame_curr, font=("helvetica", 13), width=60, height=6, spacing1=3,
                                     bg="#1F2833", fg="#C5C6C7")
            self.regex_widget.grid(row=0, column=0)

            # Print current regex patterns
            for i in range(self.regex_list['length']):
                self.regex_widget.insert(END, f"{self.regex_list['entities'][i]} - {self.regex_list['names_pattern'][i]} - "
                                              f"{self.regex_list['patterns'][i]} - {self.regex_list['scores'][i]} - "
                                              f"{self.regex_list['context_words'][i]}\n")
            self.regex_widget.configure(state='disabled')

    def setup_deny_list(self):
        if len(self.entity.get()) > 2 and len(self.values.get()) > 2:
            self.deny_list['supported_entities'].append(self.entity.get())
            self.deny_list['values_list'].append(self.values.get())
            self.deny_list['length'] += 1
            self.deny_widget.configure(state='normal')
            self.deny_widget.insert(END, f"{self.entity.get()} - {self.values.get()}\n")
            self.deny_widget.configure(state='disabled')
            messagebox.showinfo(parent=self.settings, title="Save", message=f"Deny list for {self.entity.get()} saved!")
        else:
            messagebox.showerror(parent=self.settings, title="Error", message="Compile all the fields!")

    def clear_deny_config(self):
        answer = messagebox.askyesno(parent=self.settings, title=None,
                                     message="Do you want to reset deny list configuration?")

        if answer:
            self.deny_list['supported_entities'] = []
            self.deny_list['values_list'] = []
            self.deny_list['length'] = 0

            self.deny_widget.configure(state='normal')
            self.deny_widget.delete("1.0", END)
            self.deny_widget.configure(state='disabled')

    def setup_regex_list(self):
        if len(self.entity_regex.get()) > 2:
            self.regex_list['entities'].append(self.entity_regex.get())
            self.regex_list['names_pattern'].append(self.name_pattern.get())
            self.regex_list['patterns'].append(self.regex.get())
            self.regex_list['scores'].append(self.score_regex.get())
            self.regex_list['context_words'].append(self.context.get())
            self.regex_list['length'] += 1
            self.regex_widget.configure(state='normal')
            self.regex_widget.insert(END, f"{self.entity_regex.get()} - {self.name_pattern.get()} "
                                          f"- {self.regex.get()} - {self.score_regex.get()} - {self.context.get()}\n")
            self.regex_widget.configure(state='disabled')
            messagebox.showinfo(parent=self.settings, title="Save",
                                message=f"Regex for {self.entity_regex.get()} saved!")
        else:
            messagebox.showerror(parent=self.settings, title="Error", message="Compile all the fields!")

    def clear_regex_config(self):
        answer = messagebox.askyesno(parent=self.settings, title=None,
                                     message="Do you want to reset regex configuration?")

        if answer:
            self.regex_list['entities'] = []
            self.regex_list['names_pattern'] = []
            self.regex_list['patterns'] = []
            self.regex_list['scores'] = []
            self.regex_list['context_words'] = []
            self.regex_list['length'] = 0

            self.regex_widget.configure(state='normal')
            self.regex_widget.delete("1.0", END)
            self.regex_widget.configure(state='disabled')


if __name__ == '__main__':
    root_tk = Tk()
    app = Frames(root_tk)
    root_tk.mainloop()
