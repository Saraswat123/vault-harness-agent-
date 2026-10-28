"""Opt-in OpenTelemetry tracing to Phoenix. Off unless PHOENIX_COLLECTOR_ENDPOINT is set. Never raises."""
import os

_done = False


def enable(project: str = "vault-harness") -> bool:
    global _done
    ep = os.environ.get("PHOENIX_COLLECTOR_ENDPOINT")
    if _done or not ep:
        return _done
    try:
        from openinference.instrumentation.langchain import LangChainInstrumentor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(resource=Resource.create({"openinference.project.name": project}))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=ep.rstrip("/") + "/v1/traces")))
        LangChainInstrumentor().instrument(tracer_provider=provider)
        _done = True
    except Exception as e:
        print(f"tracing disabled: {type(e).__name__}: {e}")
    return _done
