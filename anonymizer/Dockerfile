FROM ubuntu:20.04

RUN apt-get update -y
RUN apt-get install -y python3-pip python3-dev 
RUN pip3 install --upgrade pip

RUN mkdir /anonymizer 
WORKDIR /anonymizer
COPY . /anonymizer

RUN chmod 777 /anonymizer/anonymizer-temp

RUN pip3 install -r requirements.txt
#RUN export LC_ALL=C.UTF-8  && export LANG=C.UTF-8 && python3 -m spacy download en_core_web_lg
#RUN python3 -m spacy download en_core_web_lg

RUN useradd app
USER app

ENTRYPOINT [ "python3","-u","anonymizer_server.py" ]