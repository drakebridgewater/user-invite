FROM python:3.13-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/app.py .
USER 1000:1000
VOLUME /data
EXPOSE 8080
CMD ["python", "-u", "/app/app.py"]
