import grpc
from proto import model_pb2_grpc as pb2_grpc
from proto import model_pb2 as pb2

from presidio_anonymizer import DeanonymizeEngine, AnonymizerEngine
from presidio_anonymizer.entities.engine import RecognizerResult, OperatorConfig
from presidio_anonymizer.entities.engine.result import OperatorResult

from concurrent import futures
import uuid
import json
import os

PATH_TEMP = "anonymizer-temp/"


class AnonymizerEntityServicer(pb2_grpc.AnonymizerEntityServicer):
    def __init__(self):
        self.processed_chunks = 0
        self.chunk_size = 1024 * 1024  # 1MB

    def sendFile(self, request_iterator, context):
        uuid_client = str(uuid.uuid1())
        print(f'\n[+] UUID for the client: {uuid_client}')
        print('[+] Receiving a new file...')

        self.processed_chunks = 0

        with open(f'{PATH_TEMP}{uuid_client}.txt', 'a') as f:
            for request in request_iterator:
                self.processed_chunks += self.chunk_size
                f.write(request.chunk)
        print('[+] File text received')

        return pb2.FileAck(chunks=self.processed_chunks, uuidClient=uuid_client)

    def sendRecognizerResults(self, request_iterator, context):
        uuid_client = None
        recognizer_results = {'results': list()}

        for request in request_iterator:
            if uuid_client is None:
                uuid_client = request.uuidClient
                print(f'[+] UUID client: {uuid_client}')
                print('[+] Receiving a recognizer results file...')

            recognizer_result = {
                'start': request.start,
                'end': request.end,
                'score': f'{request.score:.2f}',
                'entity_type': request.entity_type,
            }
            recognizer_results['results'].append(recognizer_result)

        with open(f'{PATH_TEMP}{uuid_client}-results.json', 'a') as f:
            f.write(json.dumps(recognizer_results))
        print('[+] File received')

        return pb2.FileAck(uuidClient=uuid_client)

    def sendAnonymizedItems(self, request_iterator, context):
        uuid_client = None
        anonymized_items = {'items': list()}

        for request in request_iterator:
            if uuid_client is None:
                uuid_client = request.uuidClient
                print(f'[+] UUID client: {uuid_client}')
                print('[+] Receiving anonymizer results file...')

            anonymized_item = {
                'start': request.start,
                'end': request.end,
                'entity_type': request.entity_type,
                'operator': request.operator
            }
            anonymized_items['items'].append(anonymized_item)

        with open(f'{PATH_TEMP}{uuid_client}-results.json', 'a') as f:
            f.write(json.dumps(anonymized_items))
        print('[+] File received')

        return pb2.FileAck(uuidClient=uuid_client)

    def sendConfig(self, request, context):
        uuid_client = request.uuidClient
        print(f'[+] UUID client: {uuid_client}')
        print('[+] Receiving a configuration file...')

        with open(f'{PATH_TEMP}{uuid_client}-config.txt', 'w') as config_file:
            config_file.write(request.operators)
        print('[+] Configuration file received')

        return pb2.FileAck(chunks=-1, uuidClient=uuid_client)

    def getText(self, request, context):
        uuid_client = request.uuidClient
        print(f'[+] UUID client: {uuid_client}')

        if request.type == 'anonymize':
            print('[+] Receiving a request for anonymization...')
            results = start_anonymization(uuid_client)
            filename = f'{PATH_TEMP}{uuid_client}-anonymized.txt'
        elif request.type == 'deanonymize':
            print('[+] Receiving a request for deanonymization...')
            results = start_deanonymization(uuid_client)
            filename = f'{PATH_TEMP}{uuid_client}-deanonymized.txt'
        else:
            print('[-] Request type error')

        if results:
            print('[+] Done successfully!\n')
            print(results.text)

            self.processed_chunks = 0
            with open(filename, 'r') as text_file:
                while True:
                    data = text_file.read(self.chunk_size)

                    if not data:
                        break

                    self.processed_chunks += self.chunk_size
                    yield make_message(data)
        else:
            # sends a NAK
            print('[-] Error during operation')
            yield pb2.DataFile(chunk='-1')

    def getItems(self, request, context):
        uuid_client = request.uuidClient
        print(f'\n[+] UUID client: {uuid_client}')
        print('[+] Receiving a request for items anonymized...')

        with open(f'{PATH_TEMP}{uuid_client}-items.json', 'r') as items_file:
            items_list = json.loads(items_file.read())['results']

            for item in items_list:
                yield pb2.Item(operator=item['operator'], entity_type=item['entity_type'], start=item['start'],
                               end=item['end'], text=item['text'])

        print('[+] Operation completed!\n')

        # Cleaning temp files
        if os.path.exists(f'{PATH_TEMP}{uuid_client}-config.txt'):
            os.remove(f'{PATH_TEMP}{uuid_client}-config.txt')

        if request.type == 'anonymize':
            os.remove(f'{PATH_TEMP}{uuid_client}-anonymized.txt')
        else:
            os.remove(f'{PATH_TEMP}{uuid_client}-deanonymized.txt')

        os.remove(f'{PATH_TEMP}{uuid_client}.txt')
        os.remove(f'{PATH_TEMP}{uuid_client}-results.json')
        os.remove(f'{PATH_TEMP}{uuid_client}-items.json')


def make_message(msg):
    return pb2.DataFile(chunk=msg)


def start_anonymization(uuid_client):
    # Building recognizers list made by analyzer engine
    # checking the necessary files
    try:
        text_to_anonymize = open(f'{PATH_TEMP}{uuid_client}.txt', 'r')
    except IOError:
        print('[-] Original file text not exits')
        return -1

    recognizer_results_list = []
    try:
        with open(f'{PATH_TEMP}{uuid_client}-results.json', 'r') as recognizer_results:
            result = json.loads(recognizer_results.read())
            for res in result['results']:
                recognizer_results_list.append(RecognizerResult.from_json(res))
    except IOError:
        print('[+] File recognizer results not exists')
        return -1

    # Building operators list to perform a particular anonymization (if exists a config file
    # otherwise use a default configuration)
    config_file = 0
    try:
        config_file = open(f'{PATH_TEMP}{uuid_client}-config.txt', 'r')
    except IOError:
        print('[-] No configuration file found (using default config)')

    config_result = {}
    if config_file:
        for line in config_file:
            config_str = json.loads(line)
            # print(json.loads(config_str['params']))
            config_result[config_str['entity_type']] = OperatorConfig.from_json(json.loads(config_str['params']))
        config_file.close()

    engine = AnonymizerEngine()
    if config_file:
        result = engine.anonymize(text=text_to_anonymize.read(), analyzer_results=recognizer_results_list, operators=config_result)
    else:
        result = engine.anonymize(text=text_to_anonymize.read(), analyzer_results=recognizer_results_list)

    with open(f'{PATH_TEMP}{uuid_client}-anonymized.txt', 'w') as file_anonymized:
        file_anonymized.write(result.text)

    with open(f'{PATH_TEMP}{uuid_client}-items.json', 'w') as file_items_anonymized:
        items = {'results': list()}
        for item in result.items:
            items['results'].append(item.to_dict())
        file_items_anonymized.write(json.dumps(items))

    text_to_anonymize.close()
    return result


def start_deanonymization(uuid_client):
    try:
        text_to_deanonymize = open(f'{PATH_TEMP}{uuid_client}.txt', 'r')
    except IOError:
        print('[-] Anonymized file text not exists')
        return -1

    try:
        anonymizer_results_list = []
        with open(f'{PATH_TEMP}{uuid_client}-results.json', 'r') as anonymizer_results:  # items
            items = json.loads(anonymizer_results.read())['items']
            for item in items:
                if item['operator'] == 'encrypt':
                    anonymizer_results_list.append(OperatorResult.from_json(item))
    except IOError:
        print("[+] File recognizer results not exits")
        return -1

    # Building operators list to perform a particular deanonymization (config file is required!)
    config_file = 0
    try:
        config_file = open(f'{PATH_TEMP}{uuid_client}-config.txt', 'r')
    except IOError:
        print('[-] No configuration file found - Cannot complete the deanonymization')
        return -1

    config_result = {}
    if config_file:
        for line in config_file:
            config_str = json.loads(line)
            config_result[config_str['entity_type']] = OperatorConfig.from_json(json.loads(config_str['params']))

        config_file.close()

    engine = DeanonymizeEngine()
    result = engine.deanonymize(text=text_to_deanonymize.read(), entities=anonymizer_results_list, operators=config_result)

    with open(f'{PATH_TEMP}{uuid_client}-deanonymized.txt', 'w') as file_deanonymized:
        file_deanonymized.write(result.text)

    with open(PATH_TEMP + uuid_client + '-items.json', 'w') as anonymizer_results:
        items = {'results': list()}
        for item in result.items:
            items['results'].append(item.to_dict())
        anonymizer_results.write(json.dumps(items))

    text_to_deanonymize.close()
    return result


def run_server():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pb2_grpc.add_AnonymizerEntityServicer_to_server(AnonymizerEntityServicer(), server)

    server_port = 8061
    server.add_insecure_port(f'[::]:{server_port}')
    server.start()

    print(f'Listening on port {server_port}')
    server.wait_for_termination()


if __name__ == "__main__":
    print(':::::::::::::::::: PRESIDIO ANONYMIZER (Server) ::::::::::::::::::')
    run_server()
