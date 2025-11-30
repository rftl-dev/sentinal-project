# Use a lightweight Python version
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the dependency file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Download necessary NLP data for TextBlob (Sentiments)
RUN python -m textblob.download_corpora

# Copy the rest of the code
COPY . .

# Run the app using Gunicorn (Production Server)
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:10000"]