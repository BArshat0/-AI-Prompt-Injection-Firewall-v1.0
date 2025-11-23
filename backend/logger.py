# Updated logger.py with database integration
from sqlalchemy.orm import Session
from models import SecurityLog
from database import get_db
from typing import Dict, Any
import json
from datetime import datetime
from fastapi import Depends


class DatabaseLogger:
    def __init__(self, db: Session):
        self.db = db

    def log_request(self,
                    prompt: str,
                    risk_score: int,
                    category: str,
                    action: str,
                    user_ip: str = "unknown",
                    additional_data: Dict[str, Any] = None,
                    user_id: str = None) -> None:
        log_entry = SecurityLog(
            user_ip=user_ip,
            prompt=prompt[:500] + "..." if len(prompt) > 500 else prompt,
            risk_score=risk_score,
            category=category,
            action=action,
            user_id=user_id,
            additional_data=additional_data or {}
        )

        self.db.add(log_entry)
        self.db.commit()

    def get_logs(self, limit: int = 100, offset: int = 0) -> list:
        logs = self.db.query(SecurityLog).order_by(SecurityLog.timestamp.desc()).offset(offset).limit(limit).all()

        return [{
            "timestamp": log.timestamp.isoformat() + "Z",
            "user_ip": log.user_ip,
            "prompt": log.prompt,
            "risk_score": log.risk_score,
            "category": log.category,
            "action": log.action,
            "additional_data": log.additional_data
        } for log in logs]

    def get_stats(self) -> Dict[str, Any]:
        from sqlalchemy import func

        total_requests = self.db.query(func.count(SecurityLog.id)).scalar()
        blocked_requests = self.db.query(func.count(SecurityLog.id)).filter(
            SecurityLog.action == 'blocked'
        ).scalar()

        avg_risk = self.db.query(func.avg(SecurityLog.risk_score)).scalar() or 0

        # Category breakdown
        category_counts = self.db.query(
            SecurityLog.category,
            func.count(SecurityLog.id)
        ).group_by(SecurityLog.category).all()

        categories = {category: count for category, count in category_counts}

        return {
            "total_requests": total_requests,
            "blocked_requests": blocked_requests,
            "blocked_percentage": round((blocked_requests / total_requests * 100) if total_requests else 0, 2),
            "average_risk_score": round(avg_risk, 2),
            "category_breakdown": categories
        }


# Dependency for logger
def get_logger(db: Session = Depends(get_db)):
    return DatabaseLogger(db)