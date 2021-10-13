FROM python:latest
LABEL maintainer="Brad Atkinson <brad.scripting@gmail.com>"

RUN mkdir /code

COPY ./config.py /code
COPY ./pan_fw_build.py /code
COPY ./requirements.txt /code

WORKDIR /code

RUN pip install -r requirements.txt

CMD ["python", "-u", "pan_fw_build.py"]
