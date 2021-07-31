import analyzer_client as analyzer
import time
import os
from os import system, name

def presidio_analyzer_start(obj):
       
    print("SERVER INFO: {}:{}\n".format(obj.ip_address, obj.port))

    while True:
        print("1) Setup AnalyzerEngine")
        print("2) Setup Analyze params")
        print("3) Analyze")
        print("4) Back")

        command = int(input("\nCommand: "))

        if command == 1:
            setupEngine(obj)
            clear()

        elif command == 2:
            setupAnalyze(obj)
            clear()

        elif command == 3:

            filename = input("\nFilename: ")
            print("\nSearching for {}".format(filename))

            if obj.sendRequestAnalyze(filename) != -1:
                print("\nSuccess!")
            else:
                print("\nMissing file!")

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
        if input("\nPress q to exit: ").lower() == "q":
            clear()
            break

def setupEngine(obj):
    clear()

    if analyzer.ENGINE_CURR_CONFIG:
        print("\nENGINE CURRENT CONFIG FOUND: ")

        for elem in analyzer.ENGINE_CURR_CONFIG:
            if elem != 'uuidClient':
                print(elem + " : " +  analyzer.ENGINE_CURR_CONFIG[elem])

        print('\n')

    while True:
        print("1) PII recognition")
        print("2) Other options")
        print("3) Back")

        command = int(input("\nCommand: "))

        if command == 1:
            setupPIIRecognition(obj)

        elif command == 2:
            setupOptions(obj)
            exit()

        elif command == 3:
            clear()
            break

        else:
            print("Command not valid\n")

def setupPIIRecognition(obj):
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
            
            if "deny_list" not in analyzer.ENGINE_CURR_CONFIG:

                supported_entity = input("\nEntity: ").upper()
                
                if supported_entity == "Q":
                    print("Exiting...")
                    break
                
                print("\nNOTE: separate values with commas.\n")
                values = input("Values list: ")

                obj.setupDenyList(supported_entity, values)

            else:
                print("\nDeny-list configuration found: {}".format(analyzer.ENGINE_CURR_CONFIG['deny_list']))
                response = input("\nDo you want to reset it? [Y/N]: ").upper()

                if response == "Y":
                    analyzer.ENGINE_CURR_CONFIG.pop('deny_list')
                    print("Done")     

            exit()          

        elif command == 2:
            
            if "regex" not in analyzer.ENGINE_CURR_CONFIG:

                supported_entity = input("\nEntity: ").upper()
                
                if supported_entity == "Q":
                    print("Exiting...")
                    break

                patterns = []
                name_pattern = input("Name Pattern: ")
                regex = input("Regex: ")
                score = float(input("Score: "))
                print("\nNOTE: separate context words with commas.\n")
                context = input("Context words: ")

                patterns.append("{ " + f"\'name_pattern\' : \'{name_pattern}\', \'regex\' : \'{regex}\', \'score\' : {score}" + " }")
                obj.setupRegex(supported_entity, patterns, context)

            else:
                print("\nRegex based configuration found: {}".format(analyzer.ENGINE_CURR_CONFIG['regex']))
                response = input("\nDo you want to reset it? [Y/N]: ").upper()

                if response == "Y":
                    analyzer.ENGINE_CURR_CONFIG.pop('regex')
                    print("Done") 

            exit()                

        elif command == 3:
            clear()
            break
        else:
            print("Command not valid\n")
            clear()

def setupOptions(obj):

    if analyzer.ENGINE_CURR_CONFIG:
        print("\nANALYZER ENGINE CURRENT CONFIG FOUND: ")

        for elem in analyzer.ENGINE_CURR_CONFIG:
            if elem != 'uuidClient':
                print(elem + " : " +  analyzer.ENGINE_CURR_CONFIG[elem])

    print("\nAvailable options: \n")
    optionAvailable = ""

    for option in analyzer.ENGINE_OPTIONS:
        if option != "deny_list" and option != "regex" and option != "nlp_engine" and option != "app_tracer":
            optionAvailable += option + "\n"

    print(optionAvailable)
    print("AnalyzerEngine configuration (press Q for exit)\n")

    while True:

        option = input("Name: ").lower()

        if option == "q":
            break

        if option in analyzer.ENGINE_OPTIONS:

            if option == "log_decision_process":
                print("\nNOTE: possible values are 0 (False) or 1 (True)\n")

            value = input("Option value: ").lower()

            if option in analyzer.ENGINE_CURR_CONFIG:

                response = input("This config already exists. Do you want to update it? [Y/N]: ").upper()
                if response == "Y":
                    
                    print("Updating...")
                    obj.setupOptions(option, value, analyzer.ENGINE_CURR_CONFIG, 1)
                    print("Option {} -> {}\n".format(option, value))

                elif response == "N":
                    print("Ignoring...")
                else:
                    print("Invalid command")
                    continue

            else:
                # adding a new option
                obj.setupOptions(option, value, analyzer.ENGINE_CURR_CONFIG, 0)
                print("Option {} -> {}\n".format(option, value))

        else:
            print("Name option not valid!\n")
            continue

def setupAnalyze(obj):

    if analyzer.ANALYZE_CURR_CONFIG:
        print("\nANALYZE CURRENT CONFIG FOUND: ")

        for elem in analyzer.ANALYZE_CURR_CONFIG:
            if elem != 'uuidClient':
                print(elem + " : " +  analyzer.ANALYZE_CURR_CONFIG[elem])

    print("\nAvailable options: \n")

    for option in analyzer.ANALYZE_OPTIONS:
        print(option)

    print("\nAnalyze config (press Q for exit)")

    while True:

        option = input("\nOption name: ").lower()

        if option == "q":
            print("Exting...")
            break

        if option in analyzer.ANALYZE_OPTIONS:

            if option == "entities":
                print("\nNOTE: separate entities with commas. For example: PERSON,LOCATION,IP_ADDRESS..\n")

            if option == "return_decision_process":
                print("\nNOTE: possible values are 0 (False) or 1 (True)\n")

            value = input("Option value: ").lower()

            if option in analyzer.ANALYZE_CURR_CONFIG:

                response = input("This config already exists. Do you want to update it? [Y/N]: ").upper()
                if response == "Y":
                    
                    print("Updating...")
                    obj.setupOptions(option, value, analyzer.ANALYZE_CURR_CONFIG, 1)
                    print("Option: {} -> {}".format(option, value))

                elif response == "N":
                    print("Ignoring...")
                else:
                    print("Invalid command")
                    continue

            else:
                # adding a new option
                obj.setupOptions(option, value, analyzer.ANALYZE_CURR_CONFIG, 0)
                print("Option: {} -> {}".format(option, value))

        else:
            print("Name option not valid!")
            continue

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
                obj
                presidio_analyzer_start(obj)
            except NameError:
                print("No server info found! You must set a server configuration.")
            
        elif command == 2:

            ip_address = input("\nIP ADDRESS: ")
            port = input("SERVER PORT: ")
            
            obj = analyzer.ClientEntity(ip_address, port)
            exit()

        elif command == 3:
            print("\nQuitting..")
            time.sleep(1)
            break

        else:
            print("\nCommand not valid!\n") 
            continue