"""Criação de sessões e clientes AWS."""

import os
from typing import Optional

import boto3
from botocore.config import Config

_RETRY = Config(retries={"max_attempts": 10, "mode": "adaptive"})

# Serviços que o scan e o remediate usam. Controle novo que fala com outro serviço? Adicione aqui.
SERVICES = ("codebuild", "sagemaker", "rds", "iam", "ssm", "logs", "sts")


def session(profile: Optional[str] = None, region: Optional[str] = None) -> boto3.Session:
    profile = profile or os.getenv("AWS_PROFILE") or None
    region = region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
    return boto3.Session(profile_name=profile, region_name=region)


def client(sess: boto3.Session, service: str):
    return sess.client(service, config=_RETRY)
