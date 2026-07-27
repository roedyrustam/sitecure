from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.db.database import get_db
from app.db import models
from app.schemas import schemas

router = APIRouter(prefix="/targets", tags=["Target Assets"])

@router.get("/", response_model=List[schemas.TargetAssetResponse])
def get_targets(db: Session = Depends(get_db)):
    return db.query(models.TargetAsset).order_by(models.TargetAsset.id.desc()).all()

@router.post("/", response_model=schemas.TargetAssetResponse, status_code=status.HTTP_201_CREATED)
def create_target(target: schemas.TargetAssetCreate, db: Session = Depends(get_db)):
    db_target = models.TargetAsset(**target.model_dump())
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    return db_target

@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(models.TargetAsset).filter(models.TargetAsset.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target asset not found")
    db.delete(target)
    db.commit()
    return None
