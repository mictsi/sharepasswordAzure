#!/usr/bin/env bash
set -euo pipefail

PROJECT_PATH="${1:-./sharepasswordAzure/sharepasswordAzure.csproj}"
URLS="${2:-}"
CONFIGURATION="${3:-Debug}"
ENVIRONMENT="${4:-Development}"

echo "Restoring dependencies..."
dotnet restore

echo "Building project (${CONFIGURATION})..."
dotnet build "$PROJECT_PATH" -c "$CONFIGURATION"

export ASPNETCORE_ENVIRONMENT="$ENVIRONMENT"
echo "ASPNETCORE_ENVIRONMENT=$ENVIRONMENT"

if [[ -z "$URLS" ]]; then
	echo "Starting sharepasswordAzure using URL/port from appsettings"
	echo "Pass arg2 to override URL (example: ./start-linux.sh ./sharepasswordAzure/sharepasswordAzure.csproj http://localhost:5099)"
	echo "Press Ctrl+C to stop."
	dotnet run --project "$PROJECT_PATH" -c "$CONFIGURATION" --no-launch-profile
	exit $?
fi

echo "Starting sharepasswordAzure on $URLS"
echo "Press Ctrl+C to stop."

dotnet run --project "$PROJECT_PATH" -c "$CONFIGURATION" --no-launch-profile --urls "$URLS"
