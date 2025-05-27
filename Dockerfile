FROM python:3.13 AS build
# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.7.8 /uv /uvx /bin/
WORKDIR /code
# Set uv environment variables for production
ENV UV_PROJECT_ENVIRONMENT=/code/.venv
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
# Copy code
COPY . .
# Install dependencies
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13-slim
# Copy the virtual environment from build stage
COPY --from=build /code/.venv /code/.venv
# Set PATH to use virtual environment
ENV PATH="/code/.venv/bin:$PATH"
ENTRYPOINT ["acme-nginx"]
