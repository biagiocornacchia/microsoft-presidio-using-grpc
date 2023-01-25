import grpc
from proto import model_pb2_grpc as pb2_grpc
from proto import model_pb2 as pb2
from google.protobuf.json_format import Parse

import json
import os

ENGINE_OPTIONS = [
    'deny_list',
    'regex',
    'nlp_engine',
    'app_tracer',
    'log_decision_process',
    'default_score_threshold',
    'supported_languages'
]
ANALYZER_OPTIONS = [
    'language',
    'entities',
    'correlation_id',
    'score_threshold',
    'return_decision_process'
]

PATH_RESULTS = os.path.join(os.path.abspath('..'), 'analyzer-results', '')
PATH_FILES = os.path.join(os.path.abspath('..'), 'files', '')


class ClientEntity:
    def __init__(self, ip_address: str, port: int) -> None:
        self.processed_chunks = 0
        self.chunk_size = 1024 * 1024  # 1MB

        self.ip_address = ip_address
        self.port = port
        self.channel = grpc.insecure_channel(f'{ip_address}:{port}')
        self.stub = pb2_grpc.AnalyzerEntityStub(self.channel)

        self.engine_current_config = {}
        self.analyzer_current_config = {}

    def send_analyzer_request(self, filename: str) -> int:
        if not self.check_required_files(filename):
            return -1

        try:
            # Sending original text file to analyze
            chunk_iterator = self.generate_file_chunks(filename)
            print('\nFROM CLIENT: sending original text...')
            response = self.stub.sendFileToAnalyze(chunk_iterator)

            if response.chunks == self.processed_chunks:
                print(f'FROM SERVER: file received correctly. UUID assigned: {response.uuidClient}')
                my_uuid = response.uuidClient

                # Sending configuration options (if not empty)
                if self.engine_current_config:
                    print('FROM CLIENT: sending AnalyzerEngine configuration...')
                    self.engine_current_config['uuidClient'] = my_uuid
                    json_msg = json.dumps(self.engine_current_config)
                    response = self.stub.sendEngineOptions(Parse(json_msg, pb2.AnalyzerEngineOptions()))

                if self.analyzer_current_config:
                    print('FROM CLIENT: sending analyze configuration...')
                    self.analyzer_current_config['uuidClient'] = my_uuid
                    json_msg = json.dumps(self.analyzer_current_config)
                    response = self.stub.sendOptions(Parse(json_msg, pb2.AnalyzeOptions()))

                responses = self.stub.getAnalyzerResults(pb2.Request(uuidClient=my_uuid))
                print('FROM CLIENT: waiting for analyzer results...')

                with open(f'{PATH_RESULTS}{filename}-results.json', 'w') as recognizer_results:
                    analyzer_result = {'results': list()}

                    for response in responses:
                        entity = {
                            'start': response.start,
                            'end': response.end,
                            'score': f'{response.score:.2f}',
                            'entity_type': response.entity_type,
                            'analysis_explanation': response.analysis_explanation
                        }
                        analyzer_result['results'].append(entity)

                    recognizer_results.write(json.dumps(analyzer_result))
                print(f'\n{filename}-results.json created')
                return 1
            else:
                print('FROM SERVER: original text file not received correctly')
                return 0
        except grpc.RpcError as rpc_error:
            if rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
                print('Cannot connect to the server')
            else:
                print(f'Received unknown RPC error: code={rpc_error.code()} message={rpc_error.details()}\n')
            return -2

    def generate_file_chunks(self, filename: str) -> iter:
        self.processed_chunks = 0

        with open(f'{PATH_FILES}{filename}.txt', 'r') as textToAnalyze:
            while True:
                data = textToAnalyze.read(self.chunk_size)

                if not data:
                    break

                self.processed_chunks += self.chunk_size
                yield pb2.DataFile(chunk=data)

    def check_required_files(self, filename: str) -> bool:
        # Check text file
        if not os.path.exists(f'{PATH_FILES}{filename}.txt'):
            print('[-] ERROR: file text not found!')
            return False

        # Check configuration setup (AnalyzerEngine and Analyze params)
        if self.engine_current_config:
            print('AnalyzerEngine configuration found')
            # print(self.engine_curr_config)
        else:
            print('AnalyzerEngine configuration not found')

        if self.analyzer_current_config:
            print('Analyze configuration found')
            # print(self.analyzer_current_config)
        else:
            print('Analyze configuration not found')

        return True

    def setup_deny_list(self, supported_entities: list, values_list: list) -> None:
        deny_list = {
            'supported_entity': supported_entities,
            'deny_list': values_list
        }
        self.engine_current_config['deny_list'] = json.dumps(deny_list)

    def setup_regex(self, supported_entity: list, patterns: list, context: list) -> None:
        regex = {
            'supported_entity': supported_entity,
            'pattern': patterns,
            'context': context
        }
        self.engine_current_config['regex'] = json.dumps(regex)

    def setup_options(self, option: str, value: str, option_file: str) -> int:
        if option_file == 'ANALYZE_OPTIONS':
            if option in ANALYZER_OPTIONS:
                self.analyzer_current_config[option] = value
                return 1
            else:
                # invalid option name
                return -1
        elif option_file == 'ENGINE_OPTIONS':
            if option in ENGINE_OPTIONS:
                self.engine_current_config[option] = value
                return 1
            else:
                # invalid option name
                return -1
        else:
            # invalid option_file
            return -2

    def close_connection(self):
        print('Disconnected from the server')
        self.channel.close()


# ----------------- Utility Functions -----------------
def create_pattern_info(number_of_regex: int, name_list: list, regex_list: list, score_list: list) -> list:
    patterns = list()

    for i in range(0, number_of_regex):
        pattern = {
            'name_pattern': name_list[i],
            'regex': regex_list[i],
            'score': score_list[i]
        }
        patterns.append(pattern)

    return patterns
