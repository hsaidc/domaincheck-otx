FROM python:3.10-slim

# Working directory
WORKDIR /app

# Environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install dependencies
COPY . .
RUN pip install --upgrade pip && pip install -r requirements.txt
RUN python manage.py makemigrations && python manage.py migrate
