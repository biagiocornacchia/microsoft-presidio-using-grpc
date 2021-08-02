import analyzer_client as analyzer
import time
import os
from os import system, name

def presidio_analyzer_start(clientAnalyzer):
       
    print("SERVER INFO: {}:{}\n".format(clientAnalyzer.ip_address, clientAnalyzer.port))

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
            filename = input("\nFilename: ")
            print("\nSearching for {}".format(filename))

            result = clientAnalyzer.sendRequestAnalyze(filename)

            if result == -1:
                print("\nMissing file!")
            elif result == 0:
                print("\nOriginal text file not received correctly")
            elif result == -2:
                print("\nConnection error")
            else:
                print("\nSuccess!")

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

    if clientAnalyzer.engine_curr_config:
        print("\nENGINE CURRENT CONFIG FOUND: ")

        for elem in clientAnalyzer.engine_curr_config:
            if elem != 'uuidClient':
                print(elem + " : " +  clientAnalyzer.engine_curr_config[elem])

        print('\n')

    while True:
        print("1) PII recognition")
        print("2) Other options")
        print("3) Back")

        command = int(input("\nCommand: "))

        if command == 1:
            setupPIIRecognition(clientAnalyzer)

        elif command == 2:
            setupOptions(clientAnalyzer)
            exit()

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
            
            if "deny_list" not in clientAnalyzer.engine_curr_config:

                supported_entities = []
                valuesList = []

                while True:
                    supported_entity = input("\nEntity: ").upper()
                    
                    if supported_entity == "Q":
                        print("Exiting...")
                        break
                    
                    print("\nNOTE: separate values with commas.\n")
                    values = input("Values list: ")

                    supported_entities.append(supported_entity)
                    valuesList.append(values)

                clientAnalyzer.setupDenyList(supported_entities, valuesList)

            else:

                print("\nDeny-list configuration found: {}".format(clientAnalyzer.engine_curr_config['deny_list']))
                response = input("\nDo you want to reset it? [Y/N]: ").upper()

                if response == "Y":
                    clientAnalyzer.engine_curr_config.pop('deny_list')
                    print("Done")     

            exit()          

        elif command == 2:
            
            if "regex" not in clientAnalyzer.engine_curr_config:

                supported_entity = input("\nEntity: ").upper()
                
                if supported_entity == "Q":
                    print("Exiting...")
                    break

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

            else:

                print("\nRegex based configuration found: {}".format(clientAnalyzer.engine_curr_config['regex']))
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
        print("\nANALYZER ENGINE CURRENT CONFIG FOUND: ")

        for elem in clientAnalyzer.engine_curr_config:
            if elem != 'uuidClient':
                print(elem + " : " +  clientAnalyzer.engine_curr_config[elem])

    print("\nAvailable options: \n")
    print("log_decision_process: possible values are 0 (False) or 1 (True)")
    print("default_score_threshold")
    print("supported_languages")

    print("\nAnalyzerEngine configuration (press Q for exit)")

    while True:

        option = input("\nName: ").lower()

        if option == "q":
            break

        value = input("Option value: ").lower()
        
        if clientAnalyzer.setupOptions(option, value, "ENGINE_OPTIONS") == -1:
            print("Invalid option name\n")
            continue

        print("Option added: {} -> {}".format(option, value))

def setupAnalyze(clientAnalyzer):

    if clientAnalyzer.analyze_curr_config:
        print("\nANALYZE CURRENT CONFIG FOUND: ")

        for elem in clientAnalyzer.analyze_curr_config:
            if elem != 'uuidClient':
                print(elem + " : " +  clientAnalyzer.analyze_curr_config[elem])

    print("\nAvailable options: \n")
    print("language: 'en' by default")
    print("entities: separate entities with commas (for example: PERSON,LOCATION,IP_ADDRESS..)")
    print("correlation_id")
    print("score_threshold")
    print("return_decision_process: possible values are 0 (False) or 1 (True)")
    print("\nAnalyze config (press Q for exit)")

    while True:

        option = input("\nOption name: ").lower()

        if option == "q":
            print("Exting...")
            break
        
        value = input("Option value: ").lower()

        if clientAnalyzer.setupOptions(option, value, "ANALYZE_OPTIONS") == -1:
            print("Invalid option name\n")
            continue

        print("Option added: {} -> {}".format(option, value))

if __name__ == "__main__":
    
    clear()

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
            
        elif command == 2:

            ip_address = input("\nIP ADDRESS: ")
            port = input("SERVER PORT: ")
            
            clientAnalyzer = analyzer.ClientEntity(ip_address, port)
            exit()

        elif command == 3:
            print("\nQuitting..")
            time.sleep(1)
            break

        else:
            print("\nCommand not valid!\n") 
            continue