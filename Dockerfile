# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /app

# Install dependencies
# We copy the requirements folder first to leverage Docker cache
COPY requirements/ /app/requirements/
RUN pip install --no-cache-dir -r requirements/base.txt

# Copy project
COPY . /app/

# Expose port 8000
EXPOSE 8000

# The command to run the application will be in the docker-compose.yml
# But we can add a default command here for standalone use
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "Fortify_back.wsgi:application"]
