FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy package files into a gmail_connector/ subdirectory so Python can find
# the package as "gmail_connector" from the /app working directory.
COPY . ./gmail_connector/

# Default: run the renewal / polling worker as a proper package module
CMD ["python", "-m", "gmail_connector.renewal"]
