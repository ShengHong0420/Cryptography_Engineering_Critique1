FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev git curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY requirements.txt /workspace/requirements.txt

RUN pip install --upgrade pip \
    && pip install -r /workspace/requirements.txt

RUN useradd -m dev
USER dev

ENV PATH="/home/dev/.local/bin:${PATH}"

CMD ["tail", "-f", "/dev/null"]
