from service.model.pipeline.trainer.if_ import IsolationForestTrainer
from service.model.pipeline.trainer.rf import RandomForestTrainer

_REGISTRY = {
    "if": IsolationForestTrainer,
    "rf": RandomForestTrainer,
}


def get_trainer(model_type: str, **kwargs):
    if model_type not in _REGISTRY:
        raise ValueError(f"未知的 model_type: {model_type!r}，可用：{list(_REGISTRY)}")
    return _REGISTRY[model_type](**kwargs)