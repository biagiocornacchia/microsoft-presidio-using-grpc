import anonymizer_client as anonymizer

from tkinter import *
from tkinter import filedialog
from tkinter import messagebox

import json
import os
from pathlib import Path

IP_ADDRESS = 'localhost'
PORT = 8061


class Frames(object):
    def __init__(self, root):
        self.root = root
        self.root.title('Presidio Anonymizer gRPC Client')
        self.root.geometry('650x260')
        self.root.configure(bg="#0B0C10")
        self.root.resizable(0, 0)

        # Title
        frame_title = Frame(self.root, width=650, height=60, bg="#0B0C10")
        frame_title.grid(row=0, columnspan=2)

        Label(frame_title, text="Microsoft Presidio Anonymizer", font=("Helvetica", 17, "bold"), bg="#0B0C10", fg="#C5C6C7", anchor=CENTER).pack(ipady=20)

        # Anonymizer & Deanonymizer buttons
        frame_btn_anonymize = Frame(self.root, width=650, height=1, bg="#0B0C10")
        frame_btn_anonymize.grid(row=1, columnspan=2)

        Button(frame_title, text="Anonymizer", font=("Helvetica", 14), bg="#0B0C10", fg="#C5C6C7", command=self.start_anonymizer).pack(pady=22, ipadx=17, ipady=3, side=LEFT)
        Button(frame_title, text="Deanonymizer", font=("Helvetica", 14), bg="#0B0C10", fg="#C5C6C7", command=self.start_deanonymizer).pack(pady=22, ipadx=8, ipady=3, side=RIGHT)

        # Settings
        frame_btn_settings = Frame(self.root, bg="#0B0C10")
        frame_btn_settings.grid(row=2, columnspan=2)

        Button(frame_btn_settings, text="Settings", font=("Helvetica", 14), bg="#0B0C10", fg="#C5C6C7", command=self.settings).pack(pady=10, ipadx=33, ipady=3)

    def start_anonymizer(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = Path(dir_path)

        self.root.filenames = filedialog.askopenfilenames(initialdir=str(path.parent.absolute()) + "/files",
                                                          title="Select A File",
                                                          filetypes=(("txt files", "*.txt"), ("all files", "*.*")))

        if self.root.filenames:
            client_anoymizer = anonymizer.ClientEntity(IP_ADDRESS, PORT)

            # Send options if set
            filename_list = []
            for path in self.root.filenames:
                filename, ext = os.path.basename(path).split(".")
                filename_list.append(filename)

                res = client_anoymizer.send_request_anonymize(os.path.basename(filename))

                if res == -2:
                    messagebox.showerror("gRPC Server Error",
                                         "Cannot connect to the server! Check your server settings")
                    break
                elif res == -1:
                    messagebox.showerror("gRPC Server Error",
                                         "ERROR: original file text or analyzer results not found!")
                    break

            if res == 1:
                client_anoymizer.close_connection()
                self.read_anonymizer_results(filename_list)

    def start_deanonymizer(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = Path(dir_path)

        self.root.filenames = filedialog.askopenfilenames(
            initialdir=str(path.parent.absolute()) + "/anonymizer-results", title="Select A File",
            filetypes=(("txt files", "*.txt"), ("all files", "*.*")))

        if self.root.filenames:
            client_anoymizer = anonymizer.ClientEntity(IP_ADDRESS, PORT)

            filename_list = []
            for path in self.root.filenames:
                filename, ext = os.path.basename(path).split(".")
                filename_list.append(filename)

                res = client_anoymizer.send_request_deanonymize(os.path.basename(filename))

                if res == -2:
                    messagebox.showerror("gRPC Server Error",
                                         "Cannot connect to the server! Check your server settings")
                    break
                elif res == -1:
                    messagebox.showerror("gRPC Server Error",
                                         "ERROR: configuration file, anonymized file text or anonymizer items not found!")
                    break

            if res == 1:
                client_anoymizer.close_connection()
                self.read_deanonymizer_results(filename_list)

    def read_anonymizer_results(self, filename_list):
        self.result = Toplevel()
        self.result.title("Presidio Anonymizer gRPC - RESULTS")
        self.result.geometry("1200x600")
        self.result.configure(bg="#0B0C10")
        # self.result.resizable(0, 0)

        # List filename-results.txt
        frame_list = Frame(self.result, height=30)
        frame_list.pack(side=LEFT, padx=13)

        # Scrollbar
        results_scrollbar = Scrollbar(frame_list, orient=VERTICAL)

        listbox_widget = Listbox(frame_list, yscrollcommand=results_scrollbar.set, width=26, height=20, font=("Courier", 12), bg="#1F2833", fg="#C5C6C7")

        # Configure scrollbar
        results_scrollbar.config(command=listbox_widget.yview)
        results_scrollbar.pack(side=RIGHT, fill=Y)
        # End list

        # Frame that will contain results
        frame_results = Frame(self.result, bg="#0B0C10")
        frame_results.pack(side=RIGHT, pady=15, padx=10)

        self.text_widget = Text(frame_results, font=("Courier", 13), spacing1=3, width=1300, bg="#1F2833", fg="#C5C6C7")
        self.text_widget.pack(pady=10, padx=4)
        # End frame

        for filename in filename_list:
            listbox_widget.insert(END, filename + "-anonymized")
            listbox_widget.insert(END, filename + "-anonymized-items")

        listbox_widget.bind('<<ListboxSelect>>', self.result_click_event)
        listbox_widget.pack()

    def result_click_event(self, e):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = Path(dir_path)

        current_selection = e.widget.curselection()
        filename = e.widget.get(current_selection)

        if 'anonymized-item' in filename:
            with open(str(path.parent.absolute()) + "/anonymizer-results/" + filename + ".json", "r") as results_file:
                self.text_widget.configure(state='normal')
                self.text_widget.delete("1.0", END)

                if 'anonymized-item' in filename:
                    items = json.loads(results_file.read())['items']
                    for item in items:
                        self.text_widget.insert(END, f"ENTITY TYPE: {item['entity_type']}\n"
                                                     f"OPERATOR: {item['operator']}\n"
                                                     f"TEXT: {item['text']}\n"
                                                     f"START: {item['start']}\n"
                                                     f"END: {item['end']}")
                        self.text_widget.insert(END, "\n-------------------------------------------------------------\n")
        else:
            with open(str(path.parent.absolute()) + "/anonymizer-results/" + filename + ".txt", "r") as results_file:
                self.text_widget.delete("1.0", END)
                self.text_widget.insert(END, results_file.read())

            self.text_widget.configure(state='disabled')

    def read_deanonymizer_results(self, filename_list):
        self.result = Toplevel()
        self.result.title("Presidio Anonymizer gRPC - RESULTS")
        self.result.geometry("1200x600")
        self.result.configure(bg="#0B0C10")
        # self.result.resizable(0, 0)

        # List filename-results.txt
        frame_list = Frame(self.result, height=30)
        frame_list.pack(side=LEFT, padx=13)

        # Scrollbar
        results_scrollbar = Scrollbar(frame_list, orient=VERTICAL)

        listbox_widget = Listbox(frame_list, yscrollcommand=results_scrollbar.set, width=26, height=20,
                                 font=("Courier", 12), bg="#1F2833", fg="#C5C6C7")

        # Configure scrollbar
        results_scrollbar.config(command=listbox_widget.yview)
        results_scrollbar.pack(side=RIGHT, fill=Y)
        # End list

        # Frame that will contain results
        frame_results = Frame(self.result, bg="#0B0C10")
        frame_results.pack(side=RIGHT, pady=15, padx=10)

        self.text_widget = Text(frame_results, font=("Courier", 13), spacing1=3, width=1300, bg="#1F2833", fg="#C5C6C7")
        self.text_widget.pack(pady=10, padx=4)
        # End frame

        for filename in filename_list:
            filename = filename.split("-")[0]
            listbox_widget.insert(END, filename + "-deanonymized")
            listbox_widget.insert(END, filename + "-deanonymized-items")

        listbox_widget.bind('<<ListboxSelect>>', self.result_click_event)
        listbox_widget.pack()

    def settings(self):
        self.settings = Toplevel()
        self.settings.title("Presidio Anonymizer gRPC - Settings")
        self.settings.geometry("790x430")
        self.settings.configure(bg="#0B0C10")
        self.settings.resizable(0, 0)

        ## List of options
        frame_list = Frame(self.settings, width=100, height=30)
        frame_list.pack(side=LEFT, padx=8, pady=10)

        listbox_widget = Listbox(frame_list, height=20, font=("Courier", 12), bg="#1F2833", fg="#C5C6C7")

        ## Container options 
        self.frame_options = Frame(self.settings, bg="#0B0C10")
        self.frame_options.pack(side=RIGHT, pady=15, padx=10, expand=True)

        listbox_widget.insert(0, "Server settings")
        listbox_widget.insert(1, "Anonymizer Config")
        listbox_widget.insert(2, "Deanonymizer Config")

        listbox_widget.bind('<<ListboxSelect>>', self.click_event_option)
        listbox_widget.pack()

    def click_event_option(self, e):
        current_selection = e.widget.curselection()
        option_name = e.widget.get(current_selection)

        for widget in self.frame_options.winfo_children():
            widget.destroy()

        if option_name == "Server settings":
            Label(self.frame_options, text="SERVER IP: " + IP_ADDRESS + " | SERVER PORT: " + str(PORT), font=("courier", 10), bg="#0B0C10", fg="#C5C6C7").pack(side=TOP)

            Label(self.frame_options, text="Server IP", font=("helvetica", 15), bg="#0B0C10", fg="#C5C6C7").pack(side=TOP, pady=10)
            self.server_ip = Entry(self.frame_options, font=("helvetica", 13), justify=CENTER, bd=3)
            self.server_ip.pack(anchor=S, pady=5, padx=20, ipady=2)
            Label(self.frame_options, text="Server Port", font=("helvetica", 15), bg="#0B0C10", fg="#C5C6C7").pack(side=TOP, pady=10)
            self.server_port = Entry(self.frame_options, font=("helvetica", 13), justify=CENTER, bd=3)
            self.server_port.pack(anchor=S, pady=5, padx=20, ipady=2)

            Button(self.frame_options, text="Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.setup_server).pack(side=TOP, ipadx=10, pady=10)

            if IP_ADDRESS != "null" and PORT != "null":
                self.server_ip.insert(0, IP_ADDRESS)
                self.server_port.insert(0, f'{PORT}')

        elif option_name == "Anonymizer Config":

            frame_menu = Frame(self.frame_options, bg="#0B0C10")
            frame_menu.grid(row=0, column=0, padx=12)

            self.frame_insert_option = Frame(self.frame_options, width=300, height=150, bg="#0B0C10")
            self.frame_insert_option.grid(row=0, column=1, padx=12)

            # Menu options
            self.value_inside = StringVar()

            # Set the default value of the variable
            self.value_inside.set("Select an option")

            operator = OptionMenu(frame_menu, self.value_inside, "Select an option", *("Replace", "Redact", "Mask", "Encrypt", "Hash"), command=self.change_option)
            operator.pack()

            self.frameCurr = Frame(self.frame_options, width=520, height=100, bg="#0B0C10")
            self.frameCurr.grid(row=1, columnspan=2, pady=7)

            self.anonymizer_options = Text(self.frameCurr, font=("helvetica", 13), width=60, height=7, spacing1=3, bg="#1F2833", fg="#C5C6C7")
            self.anonymizer_options.grid(row=0, column=0)

            dir_path = os.path.dirname(os.path.realpath(__file__))
            path = Path(dir_path)

            if os.path.exists(str(path) + "/config/operator_config_anonymizer.txt"):
                with open(str(path) + "/config/operator_config_anonymizer.txt", "r") as fileConfig:
                    for line in fileConfig:
                        options = json.loads(line)
                        self.anonymizer_options.insert(END, f"ENTITY: {options['entity_type']} : {json.loads(options['params'])} \n")

                self.anonymizer_options.configure(state='disabled')

        elif option_name == "Deanonymizer Config":
            frame_menu = Frame(self.frame_options, bg="#0B0C10")
            frame_menu.grid(row=0, column=0, padx=12)

            self.frame_insert_option = Frame(self.frame_options, width=300, height=150, bg="#0B0C10")
            self.frame_insert_option.grid(row=0, column=1, padx=12)

            # Menu options
            self.value_inside = StringVar()

            # Set the default value of the variable
            self.value_inside.set("Select an option")

            operator = OptionMenu(frame_menu, self.value_inside, "Select an option", ("Decrypt"), command=self.change_option)
            operator.pack()

            self.frameCurr = Frame(self.frame_options, width=520, height=100, bg="#0B0C10")
            self.frameCurr.grid(row=1, columnspan=2, pady=7)

            self.deanonymizer_options = Text(self.frameCurr, font=("helvetica", 13), width=60, height=7, spacing1=3,
                                             bg="#1F2833", fg="#C5C6C7")
            self.deanonymizer_options.grid(row=0, column=0)

            dir_path = os.path.dirname(os.path.realpath(__file__))
            path = Path(dir_path)

            if os.path.exists(str(path) + "/config/operator_config_deanonymizer.txt"):
                with open(str(path) + "/config/operator_config_deanonymizer.txt", "r") as fileConfig:
                    for line in fileConfig:
                        options = json.loads(line)
                        self.deanonymizer_options.insert(END, f"ENTITY: {options['entity_type']} : {json.loads(options['params'])} \n")

                self.deanonymizer_options.configure(state='disabled')

    def change_option(self, e):
        for widget in self.frame_insert_option.winfo_children():
            widget.destroy()

        if self.value_inside.get() == "Replace":
            Label(self.frame_insert_option, text="ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7")\
                .grid(row=0, column=0, pady=5, padx=5)
            self.entity = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.entity.grid(row=0, column=1, pady=5)

            Label(self.frame_insert_option, text="NEW VALUE", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7")\
                .grid(row=1, column=0, pady=5, padx=5)
            self.new_value = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.new_value.grid(row=1, column=1, pady=5)

            Button(self.frame_insert_option, text="Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.setup_operator).grid(row=3, column=0, ipadx=10, pady=20)
            Button(self.frame_insert_option, text="Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.clear_anonymizer_config).grid(row=3, column=1, ipadx=10, pady=20)

        elif self.value_inside.get() == "Redact":
            Label(self.frame_insert_option, text="ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7")\
                .grid(row=0, column=0, pady=5, padx=5)
            self.entity = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.entity.grid(row=0, column=1, pady=5)

            Button(self.frame_insert_option, text="Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.setup_operator).grid(row=1, column=0, ipadx=10, pady=20)
            Button(self.frame_insert_option, text="Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.clear_anonymizer_config).grid(row=1, column=1, ipadx=10, pady=20)

        elif self.value_inside.get() == "Mask":
            Label(self.frame_insert_option, text="ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7")\
                .grid(row=0, column=0, pady=5, padx=5)
            self.entity = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.entity.grid(row=0, column=1, pady=5)

            Label(self.frame_insert_option, text="MASKING CHAR", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7")\
                .grid(row=1, column=0, pady=5, padx=5)
            self.masking_char = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.masking_char.grid(row=1, column=1, pady=5)

            Label(self.frame_insert_option, text="CHARS TO MASK", font=("helvetica", 13), bg="#0B0C10",
                  fg="#C5C6C7").grid(row=2, column=0, pady=5, padx=5)
            self.chars_to_mask = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.chars_to_mask.grid(row=2, column=1, pady=5)

            Label(self.frame_insert_option, text="FROM END", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7")\
                .grid(row=3, column=0, pady=5, padx=5)
            self.from_end = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.from_end.grid(row=3, column=1, pady=5)

            Button(self.frame_insert_option, text="Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.setup_operator).grid(row=4, column=0, ipadx=10, pady=20)
            Button(self.frame_insert_option, text="Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.clear_anonymizer_config).grid(row=4, column=1, ipadx=10, pady=20)

        elif self.value_inside.get() == "Encrypt":
            Label(self.frame_insert_option, text="ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7")\
                .grid(row=0, column=0, pady=5, padx=5)
            self.entity = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.entity.grid(row=0, column=1, pady=5)

            Label(self.frame_insert_option, text="KEY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7")\
                .grid(row=1, column=0, pady=5, padx=5)
            self.key = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.key.grid(row=1, column=1, pady=5)

            Button(self.frame_insert_option, text="Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.setup_operator).grid(row=3, column=0, ipadx=10, pady=20)
            Button(self.frame_insert_option, text="Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.clear_anonymizer_config).grid(row=3, column=1, ipadx=10, pady=20)

        elif self.value_inside.get() == "Hash":
            Label(self.frame_insert_option, text="ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7")\
                .grid(row=0, column=0, pady=5, padx=5)
            self.entity = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.entity.grid(row=0, column=1, pady=5)

            Label(self.frame_insert_option, text="HASH TYPE", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7")\
                .grid(row=1, column=0, pady=5, padx=5)
            self.hash_type = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.hash_type.grid(row=1, column=1, pady=5)

            Button(self.frame_insert_option, text="Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.setup_operator).grid(row=3, column=0, ipadx=10, pady=20)
            Button(self.frame_insert_option, text="Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.clear_anonymizer_config).grid(row=3, column=1, ipadx=10, pady=20)

        elif self.value_inside.get() == "Decrypt":

            Label(self.frame_insert_option, text="ENTITY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7")\
                .grid(row=0, column=0, pady=5, padx=5)
            self.entity = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.entity.grid(row=0, column=1, pady=5)

            Label(self.frame_insert_option, text="KEY", font=("helvetica", 13), bg="#0B0C10", fg="#C5C6C7")\
                .grid(row=1, column=0, pady=5, padx=5)
            self.key = Entry(self.frame_insert_option, font=("helvetica", 13), bd=3)
            self.key.grid(row=1, column=1, pady=5)

            Button(self.frame_insert_option, text="Save", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.setup_operator).grid(row=3, column=0, ipadx=10, pady=20)
            Button(self.frame_insert_option, text="Reset", font=("helvetica", 12), bg="#0B0C10", fg="#C5C6C7",
                   command=self.clear_deanonymizer_config).grid(row=3, column=1, ipadx=10, pady=20)

    def setup_operator(self):
        res = -1
        entity = str(self.entity.get()).upper()

        if len(entity) > 2:
            if self.value_inside.get() == "Hash":
                res = anonymizer.add_hash(entity, self.hash_type.get())
            elif self.value_inside.get() == "Replace":
                res = anonymizer.add_replace(entity, self.new_value.get())
            elif self.value_inside.get() == "Redact":
                res = anonymizer.add_redact(entity)
            elif self.value_inside.get() == "Mask":
                res = anonymizer.add_mask(entity, self.masking_char.get(), self.chars_to_mask.get(),
                                          self.from_end.get())
            elif self.value_inside.get() == "Encrypt":
                res = anonymizer.add_encrypt(entity, self.key.get())
            elif self.value_inside.get() == "Decrypt":
                res = anonymizer.add_decrypt(entity, self.key.get())

            if res == 1:
                messagebox.showinfo(parent=self.settings, title="Update", message=f"Option for {entity} updated!")
            elif res == 0:
                messagebox.showinfo(parent=self.settings, title="Save", message=f"Option for {entity} saved!")
        else:
            messagebox.showerror(parent=self.settings, title="Error configuration",
                                 message=f"You have to fill in all the fields!")

    def clear_anonymizer_config(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = Path(dir_path)

        answer = messagebox.askyesno(parent=self.settings, title=None,
                                     message='Do you want to reset configuration file?')

        if answer and os.path.exists(str(path) + '/config/operator_config_anonymizer.txt'):
            os.remove(str(path) + '/config/operator_config_anonymizer.txt')
            self.anonymizer_options.configure(state='normal')
            self.anonymizer_options.delete("1.0", END)
            self.anonymizer_options.configure(state='disabled')

    def clear_deanonymizer_config(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = Path(dir_path)

        answer = messagebox.askyesno(parent=self.settings, title=None,
                                     message='Do you want to reset configuration file?')

        if answer and os.path.exists(str(path) + '/config/operator_config_deanonymizer.txt'):
            os.remove(str(path) + '/config/operator_config_deanonymizer.txt')
            self.deanonymizer_options.configure(state='normal')
            self.deanonymizer_options.delete("1.0", END)
            self.deanonymizer_options.configure(state='disabled')

    def setup_server(self):
        global IP_ADDRESS, PORT

        IP_ADDRESS = self.server_ip.get()
        PORT = self.server_port.get()

        messagebox.showinfo(parent=self.settings, title="Save", message=f"Server options saved successfully!")


if __name__ == '__main__':
    tk_root = Tk()
    app = Frames(tk_root)
    tk_root.mainloop()
