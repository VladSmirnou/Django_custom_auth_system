FROM python:3.11-bullseye

WORKDIR /django/app 

COPY . /django/app

EXPOSE 8000
# I genuinely thought that a container cannot
# use host ports for those requests

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
