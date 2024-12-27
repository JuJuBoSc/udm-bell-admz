# Base image with Python 3
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Copy requirements.txt first to leverage Docker caching
COPY ./src/requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY ./src .

# Set the default command to run your Python app
CMD ["python3", "-u", "main.py"]