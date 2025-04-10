#!/bin/bash
# k8s-deploy.sh

# Set environment
NAMESPACE="pii-guardian"

echo "=========================================="
echo "   Deploying PII Guardian to Kubernetes   "
echo "=========================================="

# Check if namespace exists, create if not
if ! kubectl get namespace $NAMESPACE &> /dev/null; then
    kubectl create namespace $NAMESPACE
    echo "Created namespace $NAMESPACE"
fi

# Apply Kubernetes configurations
echo "Applying Kubernetes configurations..."

# Apply RabbitMQ
echo "Deploying RabbitMQ..."
kubectl apply -f kubernetes/rabbitmq.yaml -n $NAMESPACE

# Wait for RabbitMQ to be ready
echo "Waiting for RabbitMQ to be ready..."
kubectl wait --for=condition=ready pod -l app=rabbitmq -n $NAMESPACE --timeout=120s || true

# Apply deployments
echo "Deploying core services..."
kubectl apply -f kubernetes/deployments/ -n $NAMESPACE

# Apply HPA
echo "Configuring auto-scaling..."
kubectl apply -f kubernetes/hpa.yaml -n $NAMESPACE

# Wait for all pods to be ready
echo "Waiting for all pods to be ready..."
kubectl wait --for=condition=ready pod -l app -n $NAMESPACE --timeout=180s || true

# Print service information
echo "Services deployed:"
kubectl get services -n $NAMESPACE

# Get API Gateway endpoint
API_ENDPOINT=$(kubectl get service api-gateway-service -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
if [ -z "$API_ENDPOINT" ]; then
    API_ENDPOINT=$(kubectl get service api-gateway-service -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
fi

if [ -z "$API_ENDPOINT" ]; then
    echo "API Gateway is not yet exposed externally."
    echo "To access it, run: kubectl port-forward service/api-gateway-service 8000:8000 -n $NAMESPACE"
else
    echo "PII Guardian API available at: http://$API_ENDPOINT:8000"
fi

echo "=========================================="
echo "Deployment complete!"
echo "=========================================="
