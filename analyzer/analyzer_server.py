import grpc
from google.protobuf.json_format import MessageToJson
from proto import model_pb2_grpc as pb2_grpc
from proto import model_pb2 as pb2

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry

import json
import os
import uuid
from concurrent import futures

ENGINE_DEFAULT_OPTIONS = {
    'registry': None,
    'regex': None,
    'deny_list': None,
    'nlp_engine': None,
    'app_tracer': None,
    'log_decision_process': 0,
    'default_score_threshold': 0,
    'supported_languages': None
}
ANALYZER_DEFAULT_OPTIONS = {
    'language': 'en',
    'entities': None,
    'correlation_id': None,
    'score_threshold': 0,
    'return_decision_process': 0,
    'ad_hoc_recognizers': None
}

PATH_TEMP = 'analyzer-temp/'


class AnalyzerEntityServicer(pb2_grpc.AnalyzerEntityServicer):
    def __init__(self):
        self.processed_chunks = 0
        self.chunk_size = 1024 * 1024  # 1MB

    def sendFileToAnalyze(self, request_iterator, context):
        # Generate a unique id for the client
        uuid_client = str(uuid.uuid1())
        print(f'[+] UUID for the client: {uuid_client}')
        print('[+] Receiving a new file...')

        self.processed_chunks = 0

        with open(f'{PATH_TEMP}{uuid_client}.txt', 'a') as f:
            for request in request_iterator:
                self.processed_chunks += self.chunk_size
                f.write(request.chunk)
        print('[+] File received')

        return pb2.Ack(chunks=self.processed_chunks, uuidClient=uuid_client)

    def sendEngineOptions(self, request, context):
        print('[+] Receiving an Engine configuration file...')

        with open(f'{PATH_TEMP}{request.uuidClient}-engineConfig.json', 'w') as engine_configuration:
            engine_configuration.write(MessageToJson(request, preserving_proto_field_name=True))
        print('[+] File received')

        return pb2.Ack(uuidClient=request.uuidClient)

    def sendOptions(self, request, context):
        print('[+] Receiving an Analyzer configuration file...')

        with open(f'{PATH_TEMP}{request.uuidClient}-analyzeConfig.json', 'w') as analyzer_configuration:
            analyzer_configuration.write(MessageToJson(request, preserving_proto_field_name=True))
        print('[+] File received')

        return pb2.Ack(uuidClient=request.uuidClient)

    def getAnalyzerResults(self, request, context):
        print('\n[+] Preparing for Presidio Analyzer')
        print(f'[+] Searching for {request.uuidClient}')

        try:
            with open(f'{PATH_TEMP}{request.uuidClient}.txt', 'r') as f:
                results = get_analyzer_result(uuid_client=request.uuidClient, file=f.read())

            os.remove(f'{PATH_TEMP}{request.uuidClient}.txt')

            for res in results:
                yield pb2.AnalyzerResults(entity_type=res.entity_type,
                                          start=res.start,
                                          end=res.end,
                                          score=res.score,
                                          analysis_explanation=str(res.analysis_explanation).replace('"', '\''))
        except IOError:
            print('[-] File not exists')


# ---------- Utility functions used by the Analyzer class ----------
def get_analyzer_result(uuid_client: str, file: str) -> list:
    # Check if the Engine configuration or the Analyzer configuration exists
    client_engine_configuration = get_engine_options(uuid_client=uuid_client)
    client_analyzer_configuration = get_analyzer_options(uuid_client=uuid_client)

    analyzer = AnalyzerEngine(
        registry=client_engine_configuration['registry'],
        nlp_engine=client_engine_configuration['nlp_engine'],  # default value
        app_tracer=client_engine_configuration['app_tracer'],  # default value
        log_decision_process=int(client_engine_configuration['log_decision_process']),
        default_score_threshold=float(client_engine_configuration['default_score_threshold']),
        supported_languages=client_engine_configuration['supported_languages']  # list of specified languages
    )
    results = analyzer.analyze(
        file,
        language=client_analyzer_configuration['language'],
        entities=client_analyzer_configuration['entities'],
        correlation_id=client_analyzer_configuration['correlation_id'],
        score_threshold=float(client_analyzer_configuration['score_threshold']),
        return_decision_process=int(client_analyzer_configuration['return_decision_process']),
        ad_hoc_recognizers=client_analyzer_configuration['ad_hoc_recognizers']  # array of objects (PatternRecognizer)
    )

    print('[+] Presidio Analyzer: DONE!')
    return results


def get_engine_options(uuid_client: str) -> dict:
    # Load default engine configuration options
    engine = ENGINE_DEFAULT_OPTIONS.copy()

    try:
        with open(f'{PATH_TEMP}{uuid_client}-engineConfig.json', 'r') as engine_configuration:
            options = json.loads(engine_configuration.read())
            custom_recognizers = []

            for elem in options:
                if elem == 'supported_languages':
                    languages = options[elem].lower()
                    engine.update({elem: languages.split(',')})
                elif elem == 'regex':
                    print('[+] Regex recognizer found')
                    regex_info = json.loads(options[elem])

                    patterns = []
                    for info in regex_info['pattern']:
                        patterns.append(
                            Pattern(name=info['name_pattern'], regex=info['regex'], score=info['score']))

                    context_list = None
                    if regex_info['context'] != '':
                        context_list = regex_info['context'].split(',')

                    custom_recognizers.append(
                        PatternRecognizer(supported_entity=regex_info['supported_entity'], patterns=patterns,
                                          context=context_list))

                elif elem == 'deny_list':
                    print('[+] Deny List recognizer found')

                    deny_info = json.loads(options[elem])
                    deny_lists = []
                    supported_entities = []

                    for entity in deny_info['supported_entity']:
                        supported_entities.append(entity)

                    for tokens in deny_info['deny_list']:
                        deny_lists.append(tokens.split(','))

                    print('\n')
                    for i in range(len(supported_entities)):
                        print(f'{i} | SUPPORTED_ENTITY: {supported_entities[i]} | DENY_LIST: {deny_lists[i]}')
                        custom_recognizers.append(
                            PatternRecognizer(supported_entity=supported_entities[i], deny_list=deny_lists[i]))
                    print('\n')
                else:
                    engine.update({elem: options[elem]})

        # Add new recognizers to the list of predefined recognizers
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers()

        for recognizer in custom_recognizers:
            registry.add_recognizer(recognizer)

        engine.update({'registry': registry})

        os.remove(f'{PATH_TEMP}{uuid_client}-engineConfig.json')
    except IOError:
        print('[+] Engine configuration not exists')

    return engine


def get_analyzer_options(uuid_client: str) -> dict:
    # Load default analyzer configuration options
    analyzer = ANALYZER_DEFAULT_OPTIONS.copy()

    try:
        with open(f'{PATH_TEMP}{uuid_client}-analyzeConfig.json', 'r') as analyzer_configuration:
            options = json.loads(analyzer_configuration.read())

            for elem in options:
                if elem == 'entities':
                    entities = options[elem].upper()
                    if entities != 'NONE':
                        analyzer.update({elem: entities.split(',')})
                else:
                    analyzer.update({elem: options[elem]})
        os.remove(f'{PATH_TEMP}{uuid_client}-analyzeConfig.json')
    except IOError:
        print('[+] Analyzer configuration not exists')

    return analyzer


# --------------------------------------------------------------------

def run_server(server_port: int) -> None:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pb2_grpc.add_AnalyzerEntityServicer_to_server(AnalyzerEntityServicer(), server)

    server.add_insecure_port(f'[::]:{server_port}')
    server.start()

    print(f'[i] Listening on port {server_port}')
    server.wait_for_termination()


if __name__ == '__main__':
    print(':::::::::::::::::: PRESIDIO ANALYZER (Server) ::::::::::::::::::')
    run_server(server_port=8061)
