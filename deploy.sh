#!/bin/bash
# Deployment script for MyCadencier Lambda Function

set -e

echo "🚀 Deploying MyCadencier Lambda Function..."

# Check prerequisites
if ! command -v serverless &> /dev/null; then
    echo "❌ Serverless CLI not found. Please install: npm install -g serverless"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker."
    exit 1
fi

if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not found. Please install AWS CLI."
    exit 1
fi

# Set deployment stage
STAGE=${1:-prod}
echo "📍 Deploying to stage: $STAGE"

# Validate AWS credentials
echo "🔐 Checking AWS credentials..."
if ! aws sts get-caller-identity &> /dev/null; then
    echo "❌ AWS credentials not configured. Run: aws configure"
    exit 1
fi

# Deploy the function
echo "📦 Building and deploying Lambda function..."
serverless deploy --stage $STAGE

if [ $? -eq 0 ]; then
    echo "✅ Deployment successful!"
    echo ""
    echo "📊 Function details:"
    serverless info --stage $STAGE
    echo ""
    echo "🧪 To test the function:"
    echo "   serverless invoke -f mycadencier-updater --stage $STAGE"
    echo ""
    echo "📝 To view logs:"
    echo "   serverless logs -f mycadencier-updater --stage $STAGE --tail"
    echo ""
    echo "🔧 Remember to configure AWS Secrets Manager with:"
    echo "   - my-google-api-credentials (Google Service Account JSON)"
    echo "   - autogreens-config (MyCadencier credentials and settings)"
else
    echo "❌ Deployment failed!"
    exit 1
fi
