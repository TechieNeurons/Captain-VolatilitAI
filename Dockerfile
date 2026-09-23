# Dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y git build-essential

# Clone Volatility 3
# RUN git clone https://github.com/volatilityfoundation/volatility3.git /volatility3
# Install volatility 3 dependencies
# RUN pip install -r /volatility3/requirements.txt

# Install our app dependencies
RUN pip install volatility3 streamlit pandas requests

CMD ["streamlit", "run", "app.py"]
