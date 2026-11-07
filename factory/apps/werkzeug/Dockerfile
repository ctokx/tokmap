FROM python:3.12-slim
ARG VERSION
RUN pip install --no-cache-dir "werkzeug==${VERSION}"
COPY app.py /app.py
EXPOSE 5000
CMD ["python", "/app.py"]
