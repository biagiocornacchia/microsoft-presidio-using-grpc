FROM ubuntu:20.04

RUN apt-get update 
RUN apt-get install -y python3-pip
RUN pip3 install --upgrade pip

RUN mkdir /analyzer 
WORKDIR /analyzer
COPY . /analyzer
RUN chmod 777 /analyzer/analyzer-temp

RUN pip3 install -r requirements.txt
RUN python3 -m spacy download en_core_web_lg

RUN useradd app
USER app

ENTRYPOINT [ "python3","-u","analyzer_server.py" ]
