#!/bin/bash

# ===================================================================
# Monarchs Chat System - Deployment Script
# ===================================================================
# This script handles production deployment of the Monarchs chat system
# Supports: Docker Compose, Manual, and Kubernetes deployments
# ===================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ===================================================================
# Helper Functions
# ===================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing=()
    
    if ! command -v docker &> /dev/null; then
        missing+=("docker")
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        missing+=("docker-compose")
    fi
    
    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing prerequisites: ${missing[*]}"
        log_info "Please install the missing tools and try again."
        exit 1
    fi
    
    log_success "All prerequisites met"
}

check_env_file() {
    log_info "Checking environment configuration..."
    
    if [ ! -f ".env" ]; then
        log_warn ".env file not found"
        log_info "Copying .env.example to .env"
        cp .env.example .env
        log_warn "Please edit .env with your configuration before running in production!"
    fi
    
    # Check for production token secret
    source .env
    if [ -z "$MONARCHS_TOKEN_SECRET" ] || [ "$MONARCHS_TOKEN_SECRET" = "your-secure-random-token-secret-here" ]; then
        log_warn "MONARCHS_TOKEN_SECRET not set or using default value"
        log_info "Generating secure token secret..."
        export MONARCHS_TOKEN_SECRET=$(openssl rand -hex 64)
        echo "MONARCHS_TOKEN_SECRET=$MONARCHS_TOKEN_SECRET" >> .env
        log_success "Generated new token secret"
    fi
    
    log_success "Environment configuration checked"
}

build_images() {
    log_info "Building Docker images..."
    
    # Build Erlang backend
    log_info "Building Erlang backend image..."
    docker build -f Dockerfile.erlang -t monarchs-erlang:latest .
    
    # Build Node.js relay
    log_info "Building Node.js relay image..."
    docker build -f Dockerfile.node -t monarchs-relay:latest .
    
    log_success "Docker images built successfully"
}

pull_images() {
    log_info "Pulling Docker images from registry..."
    
    docker pull monarchs-erlang:latest || true
    docker pull monarchs-relay:latest || true
    
    log_success "Docker images pulled"
}

deploy_docker_compose() {
    log_info "Deploying with Docker Compose..."
    
    # Stop existing containers
    log_info "Stopping existing containers..."
    docker-compose down --remove-orphans || true
    
    # Start services
    log_info "Starting services..."
    docker-compose up -d
    
    # Wait for services to be healthy
    log_info "Waiting for services to become healthy..."
    local max_attempts=30
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
            log_success "Relay service is healthy"
            break
        fi
        
        attempt=$((attempt + 1))
        log_info "Waiting for services... ($attempt/$max_attempts)"
        sleep 2
    done
    
    if [ $attempt -eq $max_attempts ]; then
        log_warn "Relay service health check timed out"
    fi
    
    log_success "Deployment complete"
}

deploy_kubernetes() {
    log_info "Deploying to Kubernetes..."
    
    if [ ! -d "k8s" ]; then
        log_error "Kubernetes manifests not found in ./k8s/"
        log_info "Please create k8s/ directory with your Kubernetes manifests"
        exit 1
    fi
    
    kubectl apply -f k8s/
    
    log_info "Waiting for deployments..."
    kubectl rollout status deployment/monarchs-erlang --timeout=120s
    kubectl rollout status deployment/monarchs-relay --timeout=120s
    
    log_success "Kubernetes deployment complete"
}

deploy_manual() {
    log_info "Manual deployment..."
    
    # Compile Erlang
    log_info "Compiling Erlang backend..."
    erlc -o src src/*.erl
    
    # Start Erlang backend
    log_info "Starting Erlang backend..."
    nohup erl -pa src -s monarchs_app -noshell -detached > /var/log/monarchs-erlang.log 2>&1
    
    # Start Node.js relay
    log_info "Starting Node.js relay..."
    NODE_ENV=production nohup npm start > /var/log/monarchs-relay.log 2>&1 &
    
    log_success "Manual deployment complete"
}

verify_deployment() {
    log_info "Verifying deployment..."
    
    local checks_passed=0
    local checks_total=4
    
    # Check relay health
    if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
        log_success "✓ Relay health check passed"
        checks_passed=$((checks_passed + 1))
    else
        log_error "✗ Relay health check failed"
    fi
    
    # Check metrics endpoint
    if curl -sf http://localhost:8080/metrics > /dev/null 2>&1; then
        log_success "✓ Metrics endpoint accessible"
        checks_passed=$((checks_passed + 1))
    else
        log_error "✗ Metrics endpoint not accessible"
    fi
    
    # Check info endpoint
    if curl -sf http://localhost:8080/info > /dev/null 2>&1; then
        log_success "✓ Info endpoint accessible"
        checks_passed=$((checks_passed + 1))
    else
        log_error "✗ Info endpoint not accessible"
    fi
    
    # Check Docker containers
    if docker-compose ps | grep -q "Up"; then
        log_success "✓ Docker containers running"
        checks_passed=$((checks_passed + 1))
    else
        log_error "✗ Docker containers not running"
    fi
    
    log_info "Verification: $checks_passed/$checks_total checks passed"
    
    if [ $checks_passed -eq $checks_total ]; then
        log_success "All deployment verification checks passed!"
        return 0
    else
        log_warn "Some verification checks failed. Please review logs."
        return 1
    fi
}

show_status() {
    echo ""
    echo "============================================"
    echo "         MONARCHS DEPLOYMENT STATUS"
    echo "============================================"
    echo ""
    
    # Service status
    echo "Service Status:"
    echo "---------------"
    curl -s http://localhost:8080/health | jq . 2>/dev/null || echo "Health check unavailable"
    echo ""
    
    # Container status
    if command -v docker-compose &> /dev/null; then
        echo "Docker Containers:"
        echo "-----------------"
        docker-compose ps
    fi
    
    echo ""
    echo "Useful Commands:"
    echo "----------------"
    echo "  View logs:    docker-compose logs -f"
    echo "  Stop:         docker-compose down"
    echo "  Restart:      docker-compose restart"
    echo "  Health:       curl http://localhost:8080/health"
    echo "  Metrics:      curl http://localhost:8080/metrics"
    echo ""
}

backup_data() {
    log_info "Creating backup..."
    
    local backup_dir="/var/backups/monarchs"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="monarchs_backup_${timestamp}.tar.gz"
    
    mkdir -p "$backup_dir"
    
    # Backup Docker volumes
    docker run --rm -v monarchs_erlang-data:/data -v "$backup_dir":/backup alpine \
        tar czf "/backup/$backup_file" -C /data . 2>/dev/null || true
    
    log_success "Backup created: $backup_dir/$backup_file"
}

restore_backup() {
    local backup_file="$1"
    
    if [ -z "$backup_file" ]; then
        log_error "Please specify a backup file to restore"
        exit 1
    fi
    
    if [ ! -f "$backup_file" ]; then
        log_error "Backup file not found: $backup_file"
        exit 1
    fi
    
    log_info "Restoring from backup: $backup_file"
    
    docker run --rm -v monarchs_erlang-data:/data -v "$(dirname $backup_file)":/backup alpine \
        tar xzf "/backup/$(basename $backup_file)" -C /data 2>/dev/null || true
    
    log_success "Backup restored"
}

scale_services() {
    local service="$1"
    local replicas="$2"
    
    if [ -z "$service" ] || [ -z "$replicas" ]; then
        log_error "Usage: ./deploy.sh scale <service> <replicas>"
        log_info "Example: ./deploy.sh scale node-relay 3"
        exit 1
    fi
    
    log_info "Scaling $service to $replicas replicas..."
    
    docker-compose scale "${service}=${replicas}" 2>/dev/null || \
    kubectl scale deployment "$service" --replicas="$replicas" 2>/dev/null || \
    log_error "Scaling not supported for this deployment method"
    
    log_success "Scaling complete"
}

rollback() {
    log_info "Rolling back to previous version..."
    
    docker-compose down
    
    # Find previous images
    local erlang_prev=$(docker images -q monarchs-erlang:* | head -2 | tail -1)
    local relay_prev=$(docker images -q monarchs-relay:* | head -2 | tail -1)
    
    if [ -n "$erlang_prev" ]; then
        docker tag "$erlang_prev" monarchs-erlang:latest
    fi
    
    if [ -n "$relay_prev" ]; then
        docker tag "$relay_prev" monarchs-relay:latest
    fi
    
    docker-compose up -d
    
    log_success "Rollback complete"
}

show_logs() {
    local service="${1:-all}"
    
    if [ "$service" = "all" ]; then
        docker-compose logs -f
    else
        docker-compose logs -f "$service"
    fi
}

usage() {
    echo ""
    echo "Monarchs Chat System - Deployment Script"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  deploy         Deploy the application (Docker Compose)"
    echo "  deploy:k8s    Deploy to Kubernetes"
    echo "  deploy:manual  Manual deployment"
    echo "  build          Build Docker images"
    echo "  pull           Pull images from registry"
    echo "  start          Start services"
    echo "  stop           Stop services"
    echo "  restart        Restart services"
    echo "  logs [service] View logs"
    echo "  status         Show deployment status"
    echo "  verify         Verify deployment"
    echo "  scale <svc> <n> Scale services"
    echo "  backup         Create data backup"
    echo "  restore <file> Restore from backup"
    echo "  rollback       Rollback to previous version"
    echo "  help           Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 deploy                    # Deploy with Docker Compose"
    echo "  $0 deploy:k8s               # Deploy to Kubernetes"
    echo "  $0 build                     # Build images"
    echo "  $0 verify                    # Verify deployment"
    echo "  $0 logs                      # View all logs"
    echo "  $0 scale node-relay 3        # Scale relay to 3 replicas"
    echo ""
}

# ===================================================================
# Main Script
# ===================================================================

main() {
    local command="${1:-deploy}"
    
    echo ""
    echo "============================================"
    echo "   MONARCHS CHAT SYSTEM - DEPLOYMENT"
    echo "============================================"
    echo ""
    
    case "$command" in
        deploy)
            check_prerequisites
            check_env_file
            pull_images
            deploy_docker_compose
            verify_deployment
            show_status
            ;;
        deploy:k8s)
            check_prerequisites
            check_env_file
            deploy_kubernetes
            ;;
        deploy:manual)
            deploy_manual
            ;;
        build)
            check_prerequisites
            check_env_file
            build_images
            ;;
        pull)
            check_prerequisites
            pull_images
            ;;
        start)
            check_prerequisites
            deploy_docker_compose
            ;;
        stop)
            log_info "Stopping services..."
            docker-compose down --remove-orphans
            log_success "Services stopped"
            ;;
        restart)
            log_info "Restarting services..."
            docker-compose restart
            log_success "Services restarted"
            ;;
        logs)
            show_logs "${2:-all}"
            ;;
        status)
            show_status
            ;;
        verify)
            verify_deployment
            ;;
        scale)
            scale_services "$2" "$3"
            ;;
        backup)
            backup_data
            ;;
        restore)
            restore_backup "$2"
            ;;
        rollback)
            rollback
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
    
    echo ""
}

# Run main function with all arguments
main "$@"

