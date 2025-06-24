#!/usr/bin/env python3
"""
MyCadencier Lambda Function
Scrapes MyCadencier product data and updates Google Sheets pricing information
Runs every 6 hours via AWS Lambda
"""

import json
import boto3
import gspread
import datetime
import logging
import os
import re
import ssl
import socket
import certifi
from typing import Dict, List, Optional, Tuple
from google.oauth2 import service_account
import requests
import time
import random
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Disable SSL warnings for custom CA bundle
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging for CloudWatch
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(name)s - %(funcName)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

# Also log to CloudWatch with structured logging
def log_execution_metrics(store_type: str, success: bool, products_count: int = 0, updated_count: int = 0, error_count: int = 0):
    """Log structured metrics for CloudWatch monitoring"""
    logger.info(f"EXECUTION_METRICS: store={store_type}, success={success}, products={products_count}, updated={updated_count}, errors={error_count}")

# Constants for column indexes
MC_REF = 2  # MyCadencier reference column
MC_MKT_UNIT = 8  # Market unit price column
MC_EXP_UNIT = 9  # Express unit price column
LAST_UPDATE_COL_MKT_MC = 18  # Last update timestamp for market MC
LAST_UPDATE_COL_EXP_MC = 19  # Last update timestamp for express MC

DEBUG = os.getenv("DEBUG", False)

def get_server_certificate_chain(hostname, port=443):
    """Get the complete certificate chain from the server"""
    logger.info(f"Downloading certificate chain for {hostname}:{port}")
    try:
        # Create SSL context that doesn't verify certificates
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect and get certificates
        with socket.create_connection((hostname, port), timeout=10) as sock:
            logger.debug(f"Connected to {hostname}:{port}")
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get the peer certificate in DER format
                der_cert = ssock.getpeercert(binary_form=True)
                
                # Parse the certificate
                cert = x509.load_der_x509_certificate(der_cert)
                
                # Convert to PEM format
                pem_cert = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                
                logger.info("Successfully retrieved server certificate")
                return [pem_cert]
    except Exception as e:
        logger.warning(f"Error getting certificate chain: {e}")
        return None

def download_intermediate_certificates(cert):
    """Download intermediate certificates from Authority Information Access"""
    intermediate_certs = []
    
    try:
        # Look for Authority Information Access extension
        try:
            aia_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            aia = aia_ext.value
            
            for access_description in aia:
                if access_description.access_method.dotted_string == "1.3.6.1.5.5.7.48.2":  # CA Issuers
                    ca_issuer_url = access_description.access_location.value
                    logger.info(f"Found CA issuer URL: {ca_issuer_url}")
                    
                    try:
                        response = requests.get(ca_issuer_url, timeout=10)
                        if response.status_code == 200:
                            # Try to parse as DER certificate
                            try:
                                intermediate_cert = x509.load_der_x509_certificate(response.content)
                                pem_cert = intermediate_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                                intermediate_certs.append(pem_cert)
                                logger.info(f"Downloaded intermediate certificate from {ca_issuer_url}")
                            except Exception as parse_error:
                                logger.warning(f"Failed to parse certificate from {ca_issuer_url}: {parse_error}")
                    except Exception as download_error:
                        logger.warning(f"Failed to download from {ca_issuer_url}: {download_error}")
        except x509.ExtensionNotFound:
            logger.info("No Authority Information Access extension found")
            
    except Exception as e:
        logger.warning(f"Error downloading intermediate certificates: {e}")
    
    return intermediate_certs

def create_complete_ca_bundle(hostname="mycadencier.carrefour.eu"):
    """
    Create a complete CA bundle with server and intermediate certificates
    """
    logger.info(f"Creating complete CA bundle for {hostname}...")
    
    try:
        # Get server certificate chain
        server_certs = get_server_certificate_chain(hostname)
        if not server_certs:
            logger.warning("Could not get server certificates, using standard CA bundle")
            return certifi.where()
        
        # Parse the server certificate to get intermediate certificates
        server_cert = x509.load_pem_x509_certificate(server_certs[0].encode('utf-8'))
        intermediate_certs = download_intermediate_certificates(server_cert)
        
        # Start with the standard certifi CA bundle
        certifi_bundle = certifi.where()
        with open(certifi_bundle, 'r') as f:
            ca_content = f.read()
        
        # Create complete CA bundle in /tmp (Lambda writable directory)
        custom_bundle_path = "/tmp/mycadencier_carrefour_eu_complete_ca_bundle.pem"
        
        with open(custom_bundle_path, 'w') as f:
            # Write standard CA certificates
            f.write(ca_content)
            
            # Add server certificate
            f.write("\n\n# MyCadencier Server Certificate\n")
            for cert in server_certs:
                f.write(cert)
                f.write("\n")
            
            # Add intermediate certificates
            if intermediate_certs:
                f.write("\n# MyCadencier Intermediate Certificates\n")
                for cert in intermediate_certs:
                    f.write(cert)
                    f.write("\n")
        
        logger.info(f"Created complete CA bundle at: {custom_bundle_path}")
        logger.info(f"Added {len(server_certs)} server certificates and {len(intermediate_certs)} intermediate certificates")
        
        return custom_bundle_path
        
    except Exception as e:
        logger.warning(f"Error creating complete CA bundle: {e}")
        # Fall back to standard certifi bundle
        return certifi.where()

class MyCadencierClient:
    """MyCadencier API Client for Lambda environment - matching working implementation"""
    
    def __init__(self, verify_ssl: bool = True, ca_bundle: str = None):
        self.base_url = "https://mycadencier.carrefour.eu"
        self.session = requests.Session()
        self.token = None
        self.username = None
        self.stores = []
        self.verify_ssl = verify_ssl
        self.ca_bundle = ca_bundle
        
        # Configure SSL verification (matching original implementation)
        if verify_ssl and ca_bundle and os.path.exists(ca_bundle):
            self.session.verify = ca_bundle
            logger.info(f"Using custom CA bundle: {ca_bundle}")
        elif verify_ssl:
            try:
                # Try to create complete CA bundle for MyCadencier
                custom_ca_bundle = create_complete_ca_bundle()
                self.session.verify = custom_ca_bundle
                logger.info("Using complete CA bundle for SSL verification")
            except Exception as e:
                logger.warning(f"Failed to create complete CA bundle: {e}")
                # Fall back to certifi's standard CA bundle
                self.session.verify = certifi.where()
                logger.info("Using standard certifi CA bundle")
        else:
            # Disable SSL verification (not recommended for production)
            self.session.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("SSL certificate verification disabled")
        
        # Set up session headers to mimic real browser (matching working implementation)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9,nl;q=0.8,fr;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Connection': 'keep-alive',
            'Sec-CH-UA': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
            'Sec-CH-UA-Mobile': '?0',
            'Sec-CH-UA-Platform': '"macOS"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
        })

    def _random_delay(self, min_seconds: float = 1.0, max_seconds: float = 3.0):
        """Add random delay to mimic human behavior"""
        delay = random.uniform(min_seconds, max_seconds)
        logger.info(f"Waiting {delay:.2f} seconds...")
        time.sleep(delay)

    def authenticate(self, username: str, password: str, store: str) -> bool:
        """Authenticate with the mycadencier API - matching working implementation"""
        logger.info(f"Starting MyCadencier authentication for user: {username[:3]}*** in store: {store}")
        
        # Add authentication-specific headers (matching working implementation)
        auth_headers = {
            'Content-Type': 'application/json;charset=UTF-8',
            'Origin': self.base_url,
            'Referer': f'{self.base_url}/client/',
            'Token': 'null'
        }
        
        # Prepare authentication payload
        auth_payload = {
            "username": username,
            "password": password,
            "store": store
        }
        
        logger.info(f"Sending authentication request to {self.base_url}/authentication/authenticate")
        
        try:
            self._random_delay(1.0, 2.0)
            
            response = self.session.post(
                f"{self.base_url}/authentication/authenticate",
                json=auth_payload,
                headers=auth_headers,
                timeout=30
            )
            
            logger.info(f"Authentication response status: {response.status_code}")
            
            if response.status_code == 200:
                auth_data = response.json()
                
                if auth_data.get('isAuthenticated', False):
                    self.token = auth_data.get('token')
                    self.username = auth_data.get('username')
                    self.stores = auth_data.get('stores', [])
                    
                    logger.info(f"Authentication successful for user: {self.username}")
                    logger.info(f"Available stores: {len(self.stores)} - Store IDs: {[store.get('id', 'unknown') for store in self.stores[:3]]}")
                    
                    # Update session headers with token
                    self.session.headers.update({'Token': self.token})
                    
                    return True
                else:
                    error_msg = auth_data.get('message', 'Unknown authentication error')
                    logger.error(f"Authentication failed: {error_msg}")
                    return False
            else:
                logger.error(f"Authentication failed with status code: {response.status_code}")
                logger.error(f"Response body: {response.text[:200]}...")  # Log first 200 chars
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Authentication request failed: {e}")
            return False

    def get_products(self, store_id: str, metier_id: str = "13") -> Optional[List[Dict]]:
        """Retrieve products for a specific store - FIXED to match working implementation"""
        if not self.token:
            logger.error("No authentication token available. Please authenticate first.")
            return None

        logger.info(f"Fetching products for store {store_id} with metier_id {metier_id}")
        
        # Add referer header for product request (matching working implementation)
        product_headers = {
            'Referer': f'{self.base_url}/client/'
        }
        
        # Prepare query parameters (matching working implementation)
        params = {
            'metierId': metier_id,
            'userID': self.username
        }
        
        logger.info(f"Sending product request to {self.base_url}/stores/{store_id}/products")
        
        try:
            self._random_delay(2.0, 4.0)
            
            start_time = time.time()
            # FIXED: Use GET method with /stores/{store_id}/products endpoint
            response = self.session.get(
                f"{self.base_url}/stores/{store_id}/products",
                params=params,
                headers=product_headers,
                timeout=60            )
            
            request_duration = time.time() - start_time
            logger.info(f"Product request completed in {request_duration:.2f} seconds with status: {response.status_code}")
            
            if response.status_code == 200:
                products = response.json()
                
                logger.info(f"Successfully retrieved {len(products)} products for store {store_id}")
                  # Log all product references
                if products:
                    product_refs = []
                    for product in products[:10]:  # Show first 10
                        original_ref = product.get('id', 'NO_ID')
                        normalized_ref = original_ref.lstrip('0') if original_ref != '0' else '0'
                        if original_ref != normalized_ref:
                            product_refs.append(f"{original_ref}({normalized_ref})")
                        else:
                            product_refs.append(original_ref)
                    
                    logger.info(f"Product references received (original/normalized): {product_refs}")
                    if len(products) > 10:
                        logger.info(f"... and {len(products) - 10} more products")
                    
                    # Log a sample product for debugging
                    sample = products[0]
                    logger.info(f"Sample product: ID={sample.get('id')}, Title={sample.get('title_fr', 'N/A')[:50]}..., BasePrice={sample.get('baseAmountPrice')}")
                else:
                    logger.warning("No products received from API")
                
                # Log product count metrics
                log_execution_metrics("products_fetched", True, len(products))
                
                return products
            else:
                logger.error(f"Failed to get products. Status code: {response.status_code}")
                logger.error(f"Response body: {response.text[:300]}...")  # Log first 300 chars
                log_execution_metrics("products_fetched", False, 0)
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Product request failed: {e}")
            log_execution_metrics("products_fetched", False, 0)
            return None

def get_aws_secret(secret_name: str, region_name: str = "eu-west-3") -> dict:
    """Fetch secret from AWS Secrets Manager or local file for testing"""
    # Check if running locally (boto3 not available or local files exist)
    local_file = f"{secret_name}.json"
    if os.path.exists(local_file):
        logger.info(f"Using local file: {local_file}")
        with open(local_file, 'r') as f:
            return json.load(f)
    
    try:
        import boto3
        client = boto3.client("secretsmanager", region_name=region_name)
        response = client.get_secret_value(SecretId=secret_name)
        return json.loads(response["SecretString"])
    except ImportError:
        logger.error(f"boto3 not available and local file {local_file} not found")
        raise FileNotFoundError(f"Cannot find {local_file} for local testing and boto3 not available")

def get_google_credentials():
    """Fetch Google API credentials from AWS Secrets Manager or local file"""
    secret_json = get_aws_secret("my-google-api-credentials")
    credentials = service_account.Credentials.from_service_account_info(secret_json)
    scope = [
        'https://spreadsheets.google.com/feeds',
        'https://www.googleapis.com/auth/spreadsheets',
        'https://www.googleapis.com/auth/drive.file',
        'https://www.googleapis.com/auth/drive'
    ]
    return credentials.with_scopes(scope)

def get_autogreens_config():
    """Fetch configuration from AWS Secrets Manager or local file"""
    return get_aws_secret("autogreens-config")

def create_product_lookup(products: List[Dict]) -> Dict[str, Dict]:
    """Create a lookup dictionary for products by reference"""
    lookup = {}
    for product in products:
        # Use 'id' as the product reference (matches MC-REF in Google Sheets)
        ref = product.get('id', '').strip()
        if ref:
            # Normalize reference - remove leading zeros for lookup
            normalized_ref = ref.lstrip('0') if ref != '0' else '0'
            
            # Store unit price and other useful info
            product_data = {
                'unit_price': product.get('baseAmountPrice', ''),  # This is the unit price
                'sales_price': product.get('salesPrice', ''),     # This is the sales price
                'title_fr': product.get('title_fr', ''),          # French title
                'title_nl': product.get('title_nl', ''),          # Dutch title
                'base_unit_fr': product.get('baseUnit_fr', ''),   # Unit (PIECE, etc.)
                'base_unit_nl': product.get('baseUnit_nl', ''),   # Unit (STUK, etc.)
                'is_promo': product.get('isPromo', False),        # Promotion status
                'status': product.get('status', ''),              # Product status
                'last_updated': datetime.datetime.now().isoformat(),
                'original_ref': ref  # Keep original reference for debugging
            }
            
            # Store using both original and normalized references for maximum compatibility
            lookup[ref] = product_data
            if normalized_ref != ref:
                lookup[normalized_ref] = product_data
                
    return lookup

def extract_price_value(price_str: str) -> Optional[float]:
    """Extract numeric price value from price string"""
    if not price_str:
        return None
    
    # Handle different price formats: "€ 1,79", "1.79", "1,79", etc.
    # Remove currency symbols and normalize
    clean_price = re.sub(r'[€$£\s]', '', str(price_str))
    
    # Replace comma with dot for decimal
    clean_price = clean_price.replace(',', '.')
    
    try:
        return float(clean_price)
    except (ValueError, TypeError):
        return None

def format_price_for_sheet(price_value: Optional[float]) -> str:
    """Format price value for Google Sheets (European format)"""
    if price_value is None:
        return "N/A"
    # Format as European style: "1,79 €" instead of "€ 1.79"
    return f"{price_value:.2f} €".replace('.', ',')

def update_sheet_with_mc_data(sheet, products_lookup: Dict[str, Dict], is_market: bool = True) -> Tuple[int, int]:
    """Update Google Sheet with MyCadencier product data"""
    logger.info(f"Updating sheet with {'market' if is_market else 'express'} MyCadencier data...")
    
    # Read all sheet data
    data = sheet.get_all_records()
    updated_count = 0
    error_count = 0
    
    # Column to update based on market type
    price_col = MC_MKT_UNIT if is_market else MC_EXP_UNIT
    timestamp_col = LAST_UPDATE_COL_MKT_MC if is_market else LAST_UPDATE_COL_EXP_MC
    
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    
    # Start from row 2 (header is row 1)
    for row_idx, row_data in enumerate(data, start=2):
        try:            # Get MC reference from the row (column index 2 = MC-REF)
            mc_ref = str(row_data.get('MC-REF', '')).strip()
            
            if not mc_ref or mc_ref == '':
                logger.debug(f"Row {row_idx}: No MC-REF found, skipping")
                continue
            
            # Normalize the reference from Google Sheets (remove leading zeros)
            normalized_mc_ref = mc_ref.lstrip('0') if mc_ref != '0' else '0'
                
            # Look up product in MyCadencier data (try both original and normalized)
            product_info = None
            lookup_ref = None
            
            if mc_ref in products_lookup:
                product_info = products_lookup[mc_ref]
                lookup_ref = mc_ref
            elif normalized_mc_ref in products_lookup:
                product_info = products_lookup[normalized_mc_ref]
                lookup_ref = normalized_mc_ref
            
            if product_info:
                base_amount_price = product_info.get('unit_price', '')
                
                # Convert to float and format for sheet
                formatted_price = format_price_for_sheet(extract_price_value(base_amount_price))                # Update the sheet
                sheet.update_cell(row_idx, price_col, formatted_price)
                sheet.update_cell(row_idx, timestamp_col, current_time)
                
                original_api_ref = product_info.get('original_ref', lookup_ref)
                logger.info(f"Updated {mc_ref}: {formatted_price} (matched API ref: {original_api_ref}, baseAmountPrice: {base_amount_price})")
                updated_count += 1
                  # 2 second delay to avoid rate limits
                time.sleep(2.0)
                
            else:
                # Product not found in MyCadencier
                sheet.update_cell(row_idx, price_col, "Not Found")
                sheet.update_cell(row_idx, timestamp_col, current_time)
                logger.warning(f"Product {mc_ref} not found in MyCadencier data")
                  # 2 second delay to avoid rate limits
                time.sleep(2.0)
                
        except Exception as e:
            logger.error(f"Error updating row {row_idx} (MC-REF: {mc_ref}): {e}")
            try:
                sheet.update_cell(row_idx, price_col, "Error")
                sheet.update_cell(row_idx, timestamp_col, f"Error: {current_time}")
                
                # 2 second delay to avoid rate limits even for errors
                time.sleep(2.0)
            except:
                pass
            error_count += 1
    
    logger.info(f"Update complete: {updated_count} updated, {error_count} errors")
    return updated_count, error_count

def process_mycadencier_store(client: MyCadencierClient, config: dict, store_type: str, sheet) -> bool:
    """Process a specific MyCadencier store (market or express)"""
    logger.info(f"=== Starting {store_type.upper()} store processing ===")
    
    is_market = store_type == "market"
    
    # Get credentials for the store type
    if is_market:
        username = config.get('mc_username_market')
        password = config.get('mc_password_market')
        store_code = config.get('mc_shop_id_market', '0538')
        target_store_id = config.get('mc_target_store_id_market', '010538')
    else:
        username = config.get('mc_username_express')
        password = config.get('mc_password_express')
        store_code = config.get('mc_shop_id_express', '0538')
        target_store_id = config.get('mc_target_store_id_express', '011431')
    
    if not all([username, password]):
        logger.error(f"Missing credentials for {store_type} store")
        log_execution_metrics(store_type, False, 0, 0, 1)
        return False
    
    logger.info(f"Processing {store_type} store - Store code: {store_code}, Target ID: {target_store_id}")
    
    # Authenticate
    auth_start = time.time()
    if not client.authenticate(username, password, store_code):
        logger.error(f"Failed to authenticate for {store_type} store")
        log_execution_metrics(store_type, False, 0, 0, 1)
        return False
    
    auth_duration = time.time() - auth_start
    logger.info(f"Authentication completed in {auth_duration:.2f} seconds")
    
    # Get products
    products_start = time.time()
    products = client.get_products(target_store_id)
    if not products:
        logger.error(f"Failed to get products for {store_type} store")
        log_execution_metrics(store_type, False, 0, 0, 1)
        return False
    
    products_duration = time.time() - products_start
    logger.info(f"Product retrieval completed in {products_duration:.2f} seconds")
    
    # Create product lookup
    lookup_start = time.time()
    products_lookup = create_product_lookup(products)
    lookup_duration = time.time() - lookup_start
    logger.info(f"Created lookup for {len(products_lookup)} products in {lookup_duration:.2f} seconds")
    
    # Update sheet
    update_start = time.time()
    updated, errors = update_sheet_with_mc_data(sheet, products_lookup, is_market)
    update_duration = time.time() - update_start
    
    logger.info(f"Sheet update completed in {update_duration:.2f} seconds")
    logger.info(f"{store_type.title()} store processing complete: {updated} updated, {errors} errors")
    
    # Log execution metrics
    log_execution_metrics(store_type, True, len(products), updated, errors)
    
    return True

def handler(event, context):
    """AWS Lambda handler function"""
    execution_start = time.time()
    logger.info("=== MyCadencier Lambda function started ===")
    logger.info(f"Lambda request ID: {context.aws_request_id if context else 'local-test'}")
    logger.info(f"Lambda function name: {context.function_name if context else 'local-test'}")
    logger.info(f"Lambda function version: {context.function_version if context else 'local-test'}")
    
    try:
        # Get configuration
        config_start = time.time()
        config = get_autogreens_config()
        config_duration = time.time() - config_start
        logger.info(f"Configuration loaded from AWS Secrets Manager in {config_duration:.2f} seconds")
        
        # Set up Google Sheets client
        sheets_start = time.time()
        creds = get_google_credentials()
        client = gspread.authorize(creds)
        sheets_duration = time.time() - sheets_start
        logger.info(f"Google Sheets client authorized in {sheets_duration:.2f} seconds")
        
        # Open the spreadsheet
        sheet_start = time.time()
        sheet_name = config.get('spreadsheet_name', 'DIALNA-ASSORTIMENT')
        sheet = client.open(sheet_name).get_worksheet(0)
        sheet_duration = time.time() - sheet_start
        logger.info(f"Opened spreadsheet '{sheet_name}' in {sheet_duration:.2f} seconds")
        
        # Initialize MyCadencier client with SSL verification enabled
        ssl_start = time.time()
        mc_client = MyCadencierClient(verify_ssl=True)
        ssl_duration = time.time() - ssl_start
        logger.info(f"MyCadencier client initialized with SSL in {ssl_duration:.2f} seconds")
        
        results = {
            "statusCode": 200,
            "body": {
                "message": "MyCadencier data update completed",
                "timestamp": datetime.datetime.now().isoformat(),
                "execution_start": datetime.datetime.fromtimestamp(execution_start).isoformat(),
                "results": {},
                "timing": {
                    "config_load": config_duration,
                    "sheets_auth": sheets_duration,
                    "sheet_open": sheet_duration,
                    "ssl_init": ssl_duration
                }
            }
        }
        
        # Process market store first
        market_start = time.time()
        market_success = False
        try:
            logger.info("=== Processing MARKET store ===")
            market_success = process_mycadencier_store(mc_client, config, "market", sheet)
            market_duration = time.time() - market_start
            results["body"]["results"]["market"] = "success" if market_success else "failed"
            results["body"]["timing"]["market_processing"] = market_duration
            logger.info(f"Market store processing completed in {market_duration:.2f} seconds: {'SUCCESS' if market_success else 'FAILED'}")
        except Exception as e:
            market_duration = time.time() - market_start
            logger.error(f"Error processing market store after {market_duration:.2f} seconds: {e}")
            results["body"]["results"]["market"] = f"error: {str(e)}"
            results["body"]["timing"]["market_processing"] = market_duration
        
        # Wait 10 seconds before processing express store to avoid API rate limiting
        delay_start = time.time()
        logger.info("Waiting 10 seconds before processing express store to avoid API rate limiting...")
        time.sleep(10)
        delay_duration = time.time() - delay_start
        results["body"]["timing"]["inter_store_delay"] = delay_duration
        
        # Process express store second
        express_start = time.time()
        express_success = False
        try:
            logger.info("=== Processing EXPRESS store ===")
            express_success = process_mycadencier_store(mc_client, config, "express", sheet)
            express_duration = time.time() - express_start
            results["body"]["results"]["express"] = "success" if express_success else "failed"
            results["body"]["timing"]["express_processing"] = express_duration
            logger.info(f"Express store processing completed in {express_duration:.2f} seconds: {'SUCCESS' if express_success else 'FAILED'}")
        except Exception as e:
            express_duration = time.time() - express_start
            logger.error(f"Error processing express store after {express_duration:.2f} seconds: {e}")
            results["body"]["results"]["express"] = f"error: {str(e)}"
            results["body"]["timing"]["express_processing"] = express_duration
        
        total_duration = time.time() - execution_start
        results["body"]["timing"]["total_execution"] = total_duration
        
        # Log final execution summary
        logger.info("=== MyCadencier Lambda function completed ===")
        logger.info(f"Total execution time: {total_duration:.2f} seconds")
        logger.info(f"Market success: {market_success}, Express success: {express_success}")
        
        # Log overall execution metrics
        overall_success = market_success and express_success
        log_execution_metrics("overall", overall_success)
        
        return results
        
    except Exception as e:
        total_duration = time.time() - execution_start
        logger.error(f"Lambda function failed after {total_duration:.2f} seconds: {e}")
        log_execution_metrics("overall", False, 0, 0, 1)
        return {
            "statusCode": 500,
            "body": {
                "error": str(e),
                "timestamp": datetime.datetime.now().isoformat(),
                "execution_start": datetime.datetime.fromtimestamp(execution_start).isoformat(),
                "execution_duration": total_duration
            }
        }

# For local testing
if __name__ == "__main__":
    # Mock event and context for local testing
    class MockContext:
        aws_request_id = "local-test-request"
        function_name = "local-test-function"
        function_version = "local-test-version"
    
    test_event = {}
    test_context = MockContext()
    
    logger.info("=== RUNNING IN LOCAL TESTING MODE ===")
    logger.info("Make sure you have these files in the current directory:")
    logger.info("  - autogreens-config.json")
    logger.info("  - my-google-api-credentials.json")
    
    result = handler(test_event, test_context)
    print(f"Result: {json.dumps(result, indent=2)}")
