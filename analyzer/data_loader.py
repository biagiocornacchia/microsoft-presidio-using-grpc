import analyzer_client as analyzer
import time
from os import system, name
import sys


def presidio_analyzer_start(client_analyzer):
    print(f'SERVER INFO: {client_analyzer.ip_address}:{client_analyzer.port}\n')

    while True:
        print('1) Setup AnalyzerEngine')
        print('2) Setup Analyze params')
        print('3) Analyze')
        print('4) Back')

        command = int(input('\nCommand: '))
        if command == 1:
            setup_engine(client_analyzer)
            clear()
        elif command == 2:
            setup_analyze(client_analyzer)
            clear()
        elif command == 3:
            filename_list = []
            num_files = int(input('\nHow many files do you want to analyze? '))

            for i in range(num_files):
                filename_list.append(input(f'{i + 1}) Filename: '))

            for filename in filename_list:
                print(f'\n=============== {filename} ANALYSES ===============\n')
                print(f'Searching for {filename}')

                result = client_analyzer.send_analyzer_request(filename)
                if result == -1:
                    print('\nERROR: missing file!')
                elif result == 0:
                    print('\nERROR: original text file not received correctly')
                elif result == -2:
                    print('\nERROR: connection error')
                else:
                    print(f'\n{filename} analyzed successfully!')
            close()
        elif command == 4:
            clear()
            break
        else:
            print('\nCommand not valid')


def clear():
    if name == 'nt':
        _ = system('cls')
    else:
        _ = system('clear')


def close():
    while True:
        if input('\nPress Q to close: ').lower() == 'q':
            clear()
            break


def setup_engine(client_analyzer):
    clear()

    while True:
        print('1) PII recognition')
        print('2) Other options')
        print('3) Back')

        command = int(input('\nCommand: '))
        if command == 1:
            setup_pii_recognition(client_analyzer)
        elif command == 2:
            setup_options(client_analyzer)
            clear()
        elif command == 3:
            clear()
            break
        else:
            print('Command not valid\n')


def setup_pii_recognition(client_analyzer):
    clear()

    while True:
        print('1) Deny-list based PII recognition')
        print('2) Regex based PII recognition')
        print('3) Back')

        try:
            command = int(input('\nCommand: '))
        except ValueError:
            print('\nYou did not enter a valid command\n')
            continue

        if command == 1:
            print('\n=============== Deny-list configuration (Ctrl-C for close) ===============')

            if 'deny_list' not in client_analyzer.engine_current_config:
                supported_entities = []
                values_list = []

                while True:
                    try:
                        supported_entity = input('\nEntity: ').upper()
                        print('\nNOTE: separate values with commas.\n')
                        values = input('Values list: ')

                        supported_entities.append(supported_entity)
                        values_list.append(values)
                    except KeyboardInterrupt:
                        print('Configuration completed')
                        time.sleep(1)
                        clear()
                        break

                client_analyzer.setup_deny_list(supported_entities, values_list)
            else:
                print(f'\nDeny-list configuration found: {client_analyzer.engine_current_config["deny_list"]}')
                response = input('\nDo you want to reset it? [Y/N]: ').upper()

                if response == 'Y':
                    client_analyzer.engine_current_config.pop('deny_list')
                    print('Done')
                close()
        elif command == 2:
            print('\n=============== Regex configuration (Ctrl-C for close) ===============')

            if 'regex' not in client_analyzer.engine_current_config:
                try:
                    supported_entity = input('\nEntity: ').upper()
                    num = int(input('\nNumber of patterns: '))

                    name_list = []
                    regex_list = []
                    score_list = []

                    for i in range(0, num):
                        name_pattern = input('\nName Pattern: ')
                        regex = input('Regex: ')
                        score = float(input('Score: '))

                        name_list.append(name_pattern)
                        regex_list.append(regex)
                        score_list.append(score)

                    print('\nNOTE: separate context words with commas.\n')
                    context = input('Context words: ')

                    patterns = analyzer.create_pattern_info(num, name_list, regex_list, score_list)

                    # Define the recognizer with one or more patterns
                    client_analyzer.setup_regex(supported_entity, patterns, context)
                except KeyboardInterrupt:
                    print('Configuration completed')
                    time.sleep(1)
                    clear()
                    break
            else:
                print(f'\nRegex based configuration found: {client_analyzer.engine_current_config["regex"]}')
                response = input('\nDo you want to reset it? [Y/N]: ').upper()

                if response == 'Y':
                    client_analyzer.engine_current_config.pop('regex')
                    print('Done')
            close()
        elif command == 3:
            clear()
            break
        else:
            print('Command not valid\n')
            clear()


def setup_options(client_analyzer):
    if client_analyzer.engine_current_config:
        print('\n=============== CURRENT CONFIGURATION ===============')

        for elem in client_analyzer.engine_current_config:
            if elem != 'uuid_client':
                print(f'[{elem}:{client_analyzer.engine_current_config[elem]}]')

    print('\n=============== AVAILABLE OPTIONS ===============\n')
    print('1) log_decision_process: possible values are 0 (False) or 1 (True)')
    print('2) default_score_threshold')
    print('3) supported_languages')

    print('\n=============== AnalyzerEngine config (Ctrl-C for close) ===============')
    while True:
        try:
            option = input('\nOption name: ').lower()
            value = input('Option value: ').lower()

            if client_analyzer.setup_options(option, value, 'ENGINE_OPTIONS') == -1:
                print('Invalid option name')
                continue

            print(f'Option added: {option} -> {value}')
        except KeyboardInterrupt:
            print('Configuration completed')
            time.sleep(1)
            break


def setup_analyze(client_analyzer):
    if client_analyzer.analyzer_current_config:
        print('\n=============== CURRENT CONFIGURATION ===============')

        for elem in client_analyzer.analyzer_current_config:
            if elem != 'uuid_client':
                print(f'{elem}:{client_analyzer.analyzer_current_config[elem]}]')

    print('\n=============== AVAILABLE OPTIONS ===============\n')
    print('1) language: \'en\' by default')
    print('2) entities: separate entities with commas (for example: PERSON,LOCATION,IP_ADDRESS.. or use \'None\' '
          'to search for all entities)')
    print('3) correlation_id')
    print('4) score_threshold')
    print('5) return_decision_process: possible values are 0 (False) or 1 (True)')

    print('\n=============== Analyze config (Ctrl-C for close) ===============')
    while True:
        try:
            option = input('\nOption name: ').lower()
            value = input('Option value: ').lower()

            if client_analyzer.setup_options(option, value, 'ANALYZE_OPTIONS') == -1:
                print('Invalid option name')
                continue

            print(f'Option added: {option} -> {value}')
        except KeyboardInterrupt:
            print('Configuration completed')
            time.sleep(1)
            break


if __name__ == "__main__":
    clear()

    try:
        while True:
            print(':::::::::::::::::: PRESIDIO ANALYZER (data loader) ::::::::::::::::::')
            print('1) Analyzer')
            print('2) Server configuration')
            print('3) Quit')

            try:
                command = int(input('\nCommand: '))
            except ValueError:
                print('\nYou did not enter a valid command\n')
                continue

            if command == 1:
                clear()
                try:
                    client_analyzer
                    presidio_analyzer_start(client_analyzer)
                except NameError:
                    print('No server info found! You must set a server configuration')
                    close()
            elif command == 2:
                print('\n=============== Server Configuration ===============\n')
                ip_address = input('IP ADDRESS: ')
                port = input('SERVER PORT: ')

                client_analyzer = analyzer.ClientEntity(ip_address, int(port))
                close()
            elif command == 3:
                print('\nQuitting...')
                break
            else:
                print('\nCommand not valid\n')
                continue
    except KeyboardInterrupt:
        print('Quitting...')
        sys.exit(0)
