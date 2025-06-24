FROM public.ecr.aws/lambda/python@sha256:2951186769ff98c4f1acf3783d9432e40cb3b03c72aab239588b3544f647bb36

# Install system dependencies for HTTP requests and TLS
RUN dnf install -y ca-certificates openssl openssl-devel

# Install Python dependencies
RUN pip install \
    boto3>=1.34.0 \
    gspread>=5.12.0 \
    google-auth>=2.23.0 \
    google-auth-oauthlib>=1.0.0 \
    google-auth-httplib2>=0.1.0 \
    requests>=2.31.0 \
    urllib3>=1.26.0 \
    certifi>=2023.7.22 \
    cryptography>=41.0.0

# Copy application code
COPY main.py ./
COPY requirements.txt ./

# Set the Lambda handler
CMD [ "main.handler" ]
