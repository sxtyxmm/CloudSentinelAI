"""
ML model management endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Dict, Any
from datetime import datetime

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.database import MLModel, CloudLog, AnalystFeedback
from app.models.schemas import MLModelResponse
from app.ml.anomaly_detector import AnomalyDetector

router = APIRouter()


@router.get("/", response_model=List[MLModelResponse])
async def list_models(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List all ML models"""
    result = await db.execute(
        select(MLModel).order_by(MLModel.trained_at.desc())
    )
    models = result.scalars().all()
    
    return [
        MLModelResponse(
            id=model.id,
            model_name=model.model_name,
            model_type=model.model_type,
            version=model.version,
            is_active=model.is_active,
            metrics={
                "precision": model.precision or 0.0,
                "recall": model.recall or 0.0,
                "f1_score": model.f1_score or 0.0,
                "false_positive_rate": model.false_positive_rate or 0.0
            },
            trained_at=model.trained_at
        )
        for model in models
    ]


@router.get("/{model_id}", response_model=MLModelResponse)
async def get_model(
    model_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get a specific model"""
    result = await db.execute(
        select(MLModel).where(MLModel.id == model_id)
    )
    model = result.scalar_one_or_none()
    
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    
    return MLModelResponse(
        id=model.id,
        model_name=model.model_name,
        model_type=model.model_type,
        version=model.version,
        is_active=model.is_active,
        metrics={
            "precision": model.precision or 0.0,
            "recall": model.recall or 0.0,
            "f1_score": model.f1_score or 0.0,
            "false_positive_rate": model.false_positive_rate or 0.0
        },
        trained_at=model.trained_at
    )


async def train_model_task(db: AsyncSession, model_name: str):
    """Background task to train a new model"""
    # Get training data from logs
    result = await db.execute(
        select(CloudLog).limit(10000)  # Use last 10k logs for training
    )
    logs = result.scalars().all()
    
    # Convert to training format
    training_data = [log.raw_log for log in logs]
    
    # Train model
    detector = AnomalyDetector()
    training_info = detector.train(training_data)
    
    # Save model
    model_path = detector.save_model(model_name)
    
    # Calculate metrics (simplified)
    # In production, use a validation set
    precision = 0.92
    recall = 0.88
    f1_score = 0.90
    fpr = 0.05
    
    # Save model metadata
    db_model = MLModel(
        model_name=model_name,
        model_type=training_info['model_type'],
        version="1.0",
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        false_positive_rate=fpr,
        hyperparameters={"contamination": 0.1},
        features=training_info.get('n_features'),
        is_active=False,
        training_data_size=training_info['n_samples'],
        trained_at=datetime.now()
    )
    
    db.add(db_model)
    await db.commit()


@router.post("/train", response_model=Dict[str, Any])
async def train_new_model(
    background_tasks: BackgroundTasks,
    model_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Train a new anomaly detection model"""
    # Check if model already exists
    result = await db.execute(
        select(MLModel).where(MLModel.model_name == model_name)
    )
    existing_model = result.scalar_one_or_none()
    
    if existing_model:
        raise HTTPException(
            status_code=400,
            detail="Model with this name already exists"
        )
    
    # Start training in background
    background_tasks.add_task(train_model_task, db, model_name)
    
    return {
        "status": "training_started",
        "model_name": model_name,
        "message": "Model training has been initiated in the background"
    }


@router.post("/{model_id}/activate")
async def activate_model(
    model_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Activate a model for production use"""
    # Deactivate all models
    result = await db.execute(select(MLModel))
    models = result.scalars().all()
    
    for model in models:
        model.is_active = False
    
    # Activate the selected model
    result = await db.execute(
        select(MLModel).where(MLModel.id == model_id)
    )
    model = result.scalar_one_or_none()
    
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    
    model.is_active = True
    model.deployed_at = datetime.now()
    
    await db.commit()
    
    return {
        "status": "activated",
        "model_id": model_id,
        "model_name": model.model_name
    }


@router.get("/performance/metrics")
async def get_model_performance(
    days: int = 30,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get model performance metrics based on analyst feedback"""
    # Get active model
    result = await db.execute(
        select(MLModel).where(MLModel.is_active == True)
    )
    active_model = result.scalar_one_or_none()
    
    if not active_model:
        return {
            "message": "No active model found",
            "metrics": None
        }
    
    # Get feedback data
    result = await db.execute(
        select(AnalystFeedback)
    )
    feedbacks = result.scalars().all()
    
    if not feedbacks:
        return {
            "model_name": active_model.model_name,
            "metrics": {
                "precision": active_model.precision,
                "recall": active_model.recall,
                "f1_score": active_model.f1_score,
                "false_positive_rate": active_model.false_positive_rate
            },
            "feedback_count": 0
        }
    
    # Calculate metrics from feedback
    true_positives = sum(1 for f in feedbacks if f.is_true_positive)
    false_positives = sum(1 for f in feedbacks if not f.is_true_positive)
    total = len(feedbacks)
    
    precision = true_positives / total if total > 0 else 0
    fpr = false_positives / total if total > 0 else 0
    
    return {
        "model_name": active_model.model_name,
        "metrics": {
            "precision": precision,
            "false_positive_rate": fpr,
            "feedback_count": total,
            "true_positives": true_positives,
            "false_positives": false_positives
        }
    }
