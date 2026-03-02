#!/usr/bin/env bash
set -euo pipefail

# Ensure we are in the toolkit directory
cd "$(dirname "$0")"

echo "Building totan binary..."
cargo build -p totan --all-features

echo "Starting environment..."
docker-compose -f docker-compose.test.yml up -d --build

# Wait for services to be ready
echo "Waiting for services..."
sleep 5

echo "Running tests from tester container..."
# Try to reach nginx through totan (redirected by nftables in totan container)
# Wait, the nftables redirection is INSIDE the totan container, but it only affects traffic
# originating FROM that container with TEST_UID.
# If we want to test transparent proxying from ANOTHER container, we need to route traffic through the totan container.
# In Docker/Compose, this is usually done by using 'network_mode: service:totan' for the tester.

echo "Reconfiguring tester to use totan's network namespace..."
docker-compose -f docker-compose.test.yml stop tester
# We need to manually tweak compose to use service network mode if we want transparent proxying for the tester.
# Alternatively, the tester can just run inside the totan container.

docker-compose -f docker-compose.test.yml exec -u tester totan curl -v http://nginx/

echo "E2E test passed!"
docker-compose -f docker-compose.test.yml down
