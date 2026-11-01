"""Cliente genérico que valida cada chamada contra o modelo do botocore e devolve respostas fixas.
Usado para testar o setup do laboratório (99) sem conta AWS."""

import botocore.session
from botocore.validate import validate_parameters

_BOTO = botocore.session.get_session()


class _Waiter:
    def __init__(self, recorder, name):
        assert name in recorder._real.waiter_names, f"waiter {name} não existe"
        self.recorder, self.name = recorder, name

    def wait(self, **kwargs):
        self.recorder.calls.append(("waiter", self.name, kwargs))


class Recorder:
    def __init__(self, service, responses=None, errors=None):
        self.service = service
        self._real = _BOTO.create_client(service, region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
        self._model = _BOTO.get_service_model(service)
        self.responses = responses or {}
        self.errors = errors or {}
        self.calls = []

    def get_waiter(self, name):
        return _Waiter(self, name)

    def get_paginator(self, name):
        assert self._real.can_paginate(name), f"{name} não é paginável"
        fn = getattr(self, name)

        class _Paginator:
            def paginate(self, PaginationConfig=None, **kwargs):  # noqa: N803
                yield fn(**kwargs)
        return _Paginator()

    def __getattr__(self, name):
        if name.startswith("_") or name not in self._real.meta.method_to_api_mapping:
            raise AttributeError(f"{self.service}.{name} não existe no boto3")
        op = self._model.operation_model(self._real.meta.method_to_api_mapping[name])

        def call(**kwargs):
            if op.input_shape is not None:
                validate_parameters(kwargs, op.input_shape)
            self.calls.append((self.service, name, kwargs))
            if name in self.errors:
                raise self.errors[name]
            return self.responses.get(name, {})
        return call
