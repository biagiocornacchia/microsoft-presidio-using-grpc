import analyzer_client as analyzer
import time
import os
from os import system, name
import sys

def presidio_analyzer_start(clientAnalyzer):
       
    print(f"SERVER INFO: {clientAnalyzer.ip_address}:{clientAnalyzer.port}\n")

    while True:
        print("1) Setup AnalyzerEngine")
        print("2) Setup Analyze params")
        print("3) Analyze")
        print("4) Back")

        command = int(input("\nCommand: "))

        if command == 1:
            setupEngine(clientAnalyzer)
            clear()
        elif command == 2:
            setupAnalyze(clientAnalyzer)
            clear()
        elif command == 3:
            filenameList = []
            numFiles = int(input("\nHow many files do you want to analyze? "))

            for i in range(numFiles):
                filenameList.append(input(f"{i+1}) Filename: "))

            for filename in filenameList:
                print(f"\n=============== {filename} ANALYSES ===============\n")
                print(f"Searching for {filename}")

                result = clientAnalyzer.sendRequestAnalyze(filename)

                if result == -1:
                    print("\nERROR: missing file!")
                elif result == 0:
                    print("\nERROR: original text file not received correctly")
                elif result == -2:
                    print("\nERROR: connection error")
                else:
                    print(f"\n{filename} analyzed successfully!")

            exit()
        elif command == 4:
            clear()
            break
        else:
            print("\nCommand not valid!")  

def clear():
    if name == "nt":
        _ = system("cls")
    else:
        _ = system("clear")

def exit():
    while True:
        if input("\nPress Q to exit: ").lower() == "q":
            clear()
            break

def setupEngine(clientAnalyzer):
    clear()

    while True:
        print("1) PII recognition")
        print("2) Other options")
        print("3) Back")

        command = int(input("\nCommand: "))

        if command == 1:
            setupPIIRecognition(clientAnalyzer)
        elif command == 2:
            setupOptions(clientAnalyzer)
            clear()
        elif command == 3:
            clear()
            break

        else:
            print("Command not valid\n")

def setupPIIRecognition(clientAnalyzer):
    clear()

    while True:
        print("1) Deny-list based PII recognition")
        print("2) Regex based PII recognition")
        print("3) Back")

        try:
            command = int(input("\nCommand: "))
        except ValueError:
            print('\nYou did not enter a valid command\n')
            continue

        if command == 1:
            
            print("\n=============== Deny-list configuration (Ctrl-C for exit) ===============")

            if "deny_list" not in clientAnalyzer.engine_curr_config:

                supported_entities = []
                valuesList = []

                while True:
                    try:
                        supported_entity = input("\nEntity: ").upper()                    
                        print("\nNOTE: separate values with commas.\n")
                        values = input("Values list: ")

                        supported_entities.append(supported_entity)
                        valuesList.append(values)
                    except KeyboardInterrupt:
                        print("Configuration completed")
                        time.sleep(1)
                        clear()
                        break

                clientAnalyzer.setupDenyList(supported_entities, valuesList)

            else:

                print(f"\nDeny-list configuration found: {clientAnalyzer.engine_curr_config['deny_list']}")
                response = input("\nDo you want to reset it? [Y/N]: ").upper()

                if response == "Y":
                    clientAnalyzer.engine_curr_config.pop('deny_list')
                    print("Done")     

                exit()          

        elif command == 2:
            print("\n=============== Regex configuration (Ctrl-C for exit) ===============") 
            
            if "regex" not in clientAnalyzer.engine_curr_config:
                try:
                    supported_entity = input("\nEntity: ").upper()
                    num = int(input("\nNumber of patterns: "))

                    nameList = []
                    regexList = []
                    scoreList = []

                    for i in range(num):
                        name_pattern = input("\nName Pattern: ")
                        regex = input("Regex: ")
                        score = float(input("Score: "))
                        
                        nameList.append(name_pattern)
                        regexList.append(regex)
                        scoreList.append(score)
                        
                    print("\nNOTE: separate context words with commas.\n")    
                    context = input("Context words: ")

                    patterns = analyzer.createPatternInfo(num, nameList, regexList, scoreList)
                    
                    # Define the recognizer with one or more patterns
                    clientAnalyzer.setupRegex(supported_entity, patterns, context)
                except KeyboardInterrupt:
                        print("Configuration completed")
                        time.sleep(1)
                        clear()
                        break
            else:

                print(f"\nRegex based configuration found: {clientAnalyzer.engine_curr_config['regex']}")
                response = input("\nDo you want to reset it? [Y/N]: ").upper()

                if response == "Y":
                    clientAnalyzer.engine_curr_config.pop('regex')
                    print("Done") 

            exit()                
        elif command == 3:
            clear()
            break
        else:
            print("Command not valid\n")
            clear()

def setupOptions(clientAnalyzer):

    if clientAnalyzer.engine_curr_config:
        print("\n=============== CURRENT CONFIGURATION ===============")

        for elem in clientAnalyzer.engine_curr_config:
            if elem != 'uuidClient':
                print("[" + elem + " : " +  clientAnalyzer.engine_curr_config[elem] + "]")

    print("\n=============== AVAILABLE OPTIONS ===============\n")
    print("1) log_decision_process: possible values are 0 (False) or 1 (True)")
    print("2) default_score_threshold")
    print("3) supported_languages")

    print("\n=============== AnalyzerEngine config (Ctrl-C for exit) ===============")

    while True:
        try:
            option = input("\nOption name: ").lower()
            value = input("Option value: ").lower()
            
            if clientAnalyzer.setupOptions(option, value, "ENGINE_OPTIONS") == -1:
                print("Invalid option name")
                continue

            print(f"Option added: {option} -> {value}")
        except KeyboardInterrupt:
            print("Configuration completed")
            time.sleep(1)
            break

def setupAnalyze(clientAnalyzer):

    if clientAnalyzer.analyze_curr_config:
        print("\n=============== CURRENT CONFIGURATION ===============")

        for elem in clientAnalyzer.analyze_curr_config:
            if elem != 'uuidClient':
                print("[" + elem + " : " +  clientAnalyzer.analyze_curr_config[elem] + "]")

    print("\n=============== AVAILABLE OPTIONS ===============\n")
    print("1) language: 'en' by default")
    print("2) entities: separate entities with commas (for example: PERSON,LOCATION,IP_ADDRESS.. or use 'None' to search for all entities)")
    print("3) correlation_id")
    print("4) score_threshold")
    print("5) return_decision_process: possible values are 0 (False) or 1 (True)")
    
    print("\n=============== Analyze config (Ctrl-C for exit) ===============")

    while True:
        try:
            option = input("\nOption name: ").lower()
            value = input("Option value: ").lower()

            if clientAnalyzer.setupOptions(option, value, "ANALYZE_OPTIONS") == -1:
                print("Invalid option name")
                continue

            print(f"Option added: {option} -> {value}")
        except KeyboardInterrupt:
            print("Configuration completed")
            time.sleep(1)
            break

if __name__ == "__main__":
    
    clear()

    try:
        while True:
            print(":::::::::::::::::: PRESIDIO ANALYZER (data loader) ::::::::::::::::::\n")
            print("1) Analyzer")
            print("2) Server configuration")
            print("3) Quit")

            try:
                command = int(input("\nCommand: "))
            except ValueError:
                print('\nYou did not enter a valid command\n')
                continue

            if command == 1:
                clear()

                try:
                    clientAnalyzer
                    presidio_analyzer_start(clientAnalyzer)
                except NameError:
                    print("No server info found! You must set a server configuration.")
                    exit()

            elif command == 2:
                print("\n=============== Server config ===============\n")
                ip_address = input("IP ADDRESS: ")
                port = input("SERVER PORT: ")
                
                clientAnalyzer = analyzer.ClientEntity(ip_address, port)
                exit()
            elif command == 3:
                print("\nQuitting..")
                break
            else:
                print("\nCommand not valid!\n") 
                continue
    except KeyboardInterrupt:
        print("Quitting...")
        sys.exit(0)