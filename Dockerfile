# Use a lightweight official Python image
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Copy the app directory contents into the container
COPY app/ /app/

# Copy the requirements file from the root directory
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port your wrapper will run on
EXPOSE 8080

# Set environment variable for port (optional)
ENV PORT=8080

# Start the app wrapper
CMD ["python", "app_wrapper.py"]