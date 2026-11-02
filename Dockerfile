# Linux image with everything the experiments need, including the Hyperledger Fabric network.
#   docker build -t pledge-artifact .
#   docker run --rm -v "$PWD/results:/pledge/results" pledge-artifact quick      (or: full)
# On Windows the .bat files run these two commands for you.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1 PYTHONUTF8=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /pledge
COPY requirements.txt ./
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt
ENV PATH=/opt/venv/bin:$PATH
# third-party tools and data in their own layer, so code changes do not download them again
COPY scripts/fetch.py scripts/fetch.py
COPY pledge/__init__.py pledge/__init__.py
COPY pledge/fhir pledge/fhir
COPY data/synthea-seed42.tar.gz data/synthea-seed42.tar.gz
RUN python scripts/fetch.py
COPY . .
RUN chmod +x fabric/bin/* && python -m unittest discover -s tests -t . 2>&1 | tail -3
ENTRYPOINT ["python", "reproduce.py"]
CMD ["quick"]
