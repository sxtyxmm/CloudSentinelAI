"""
Initialize database with sample data
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.database import AsyncSessionLocal, init_db
from app.core.security import get_password_hash
from app.models.database import User, MLModel
from datetime import datetime


async def create_sample_users():
    """Create sample users"""
    async with AsyncSessionLocal() as session:
        # Create admin user
        admin = User(
            username="admin",
            email="admin@cloudsentinel.ai",
            hashed_password=get_password_hash("admin123"),
            role="admin",
            is_active=True
        )
        session.add(admin)
        
        # Create analyst user
        analyst = User(
            username="analyst",
            email="analyst@cloudsentinel.ai",
            hashed_password=get_password_hash("analyst123"),
            role="analyst",
            is_active=True
        )
        session.add(analyst)
        
        # Create viewer user
        viewer = User(
            username="viewer",
            email="viewer@cloudsentinel.ai",
            hashed_password=get_password_hash("viewer123"),
            role="viewer",
            is_active=True
        )
        session.add(viewer)
        
        await session.commit()
        print("✓ Created sample users")


async def create_sample_model():
    """Create a sample ML model entry"""
    async with AsyncSessionLocal() as session:
        model = MLModel(
            model_name="default_anomaly_detector",
            model_type="isolation_forest",
            version="1.0",
            precision=0.92,
            recall=0.88,
            f1_score=0.90,
            false_positive_rate=0.05,
            hyperparameters={"contamination": 0.1, "n_estimators": 100},
            features=["hour_of_day", "day_of_week", "is_login_event"],
            is_active=True,
            training_data_size=10000,
            trained_at=datetime.now()
        )
        session.add(model)
        await session.commit()
        print("✓ Created sample ML model")


async def main():
    """Main initialization function"""
    print("Initializing CloudSentinelAI database...")
    
    # Initialize database tables
    await init_db()
    print("✓ Database tables created")
    
    # Create sample data
    await create_sample_users()
    await create_sample_model()
    
    print("\n✅ Database initialization complete!")
    print("\nSample credentials:")
    print("  Admin:   username=admin,   password=admin123")
    print("  Analyst: username=analyst, password=analyst123")
    print("  Viewer:  username=viewer,  password=viewer123")
    print("\n⚠️  Change these passwords in production!")


if __name__ == "__main__":
    asyncio.run(main())
