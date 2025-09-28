# Base Python image
FROM python:3.13-slim

# Install ZBar and OpenCV dependencies
RUN apt-get update && apt-get install -y \
    libzbar0 \
    libzbar-dev \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy your app files
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port (Render sets $PORT)
ENV PORT 10000
EXPOSE 10000

# Start the app with Gunicorn
CMD ["gunicorn", "backend.QRUSADERSCANNER.app:app", "--bind", "0.0.0.0:10000"]
