# LicenseGuard - Consistent execution environment for GitHub Actions
FROM python:3.12-slim

WORKDIR /app

# Install runtime dependencies (requests for Deps.dev API)
COPY action-requirements.txt .
RUN pip install --no-cache-dir -r action-requirements.txt

# Copy the scanner script (policy.json and repo requirements come from workspace at runtime)
COPY main.py .

# Run from /github/workspace so relative paths resolve to the repo
WORKDIR /github/workspace

ENTRYPOINT ["python", "/app/main.py"]
CMD ["./policy.json", "./requirements.txt"]
