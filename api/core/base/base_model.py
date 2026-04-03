from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import sqlalchemy as sa
from sqlalchemy.orm import Session, class_mapper
from uuid import uuid4
from fastapi import HTTPException
from sqlalchemy.ext.hybrid import hybrid_property
from inspect import getmembers

from api.db.database import Base
from api.utils.loggers import create_logger


logger = create_logger(__name__)

class BaseTableModel(Base):
    """This model creates helper methods for all models"""

    __abstract__ = True

    # Add flag to skip logging dynamically
    _disable_activity_logging = False
    
    id = sa.Column(sa.String, primary_key=True, index=True, default=lambda: str(uuid4().hex))
    unique_id = sa.Column(sa.String, nullable=True)
    is_deleted = sa.Column(sa.Boolean, default=False)
    created_at = sa.Column(sa.DateTime(timezone=True), default=datetime.now(timezone.utc))
    updated_at = sa.Column(sa.DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

    
    def to_dict(self, excludes: List[str] = [], visited=None) -> Dict[str, Any]:
        """Returns a dictionary representation of the instance"""
        
        # Preventing recursion error
        if visited is None:
            visited = set()

        if self.id in visited:
            logger.info(f'Recursion error prevented on table {self.__tablename__} with id {self.id}')
            return {}  # prevent infinite loop

        visited.add(self.id)
        
        obj_dict = self.__dict__.copy()
        
        del obj_dict["_sa_instance_state"]
        del obj_dict["is_deleted"]
        obj_dict["id"] = self.id
        
        if self.created_at:
            obj_dict["created_at"] = self.created_at.isoformat()
        if self.updated_at:
            obj_dict["updated_at"] = self.updated_at.isoformat()
            
        # Get hybrid properties
        for name, attr in getmembers(self):
            if isinstance(attr, hybrid_property):
                obj_dict[name] = getattr(self, name)
                
        # Exclude specified fields
        for exclude in excludes:
            if exclude in list(obj_dict.keys()):
                # for exclude in excludes:
                obj_dict.pop(exclude, None)
            
        return obj_dict
    
    @classmethod
    def load_properties(cls, db: Session, objects: list):
        """
        Override in child models if they need bulk hydration.
        Must NOT do per-object DB calls.
        """
        pass

    @classmethod
    def create(cls, db: Session, commit: bool = True, **kwargs):
        """Creates a new instance of the model"""
        
        obj = cls(**kwargs)
        db.add(obj)
        if commit:
            db.commit()
            db.refresh(obj)
        
        if hasattr(cls, "load_properties"):
            cls.load_properties(db, [obj])
            
        return obj

    @classmethod
    def all(
        cls,
        db: Session,
        page: int = 1,
        per_page: int = 10,
        sort_by: str = "created_at",
        order: str = "desc",
        show_deleted: bool = False,
        search_fields: Optional[Dict[str, Any]] = None
    ):
        """Fetches all instances with pagination and sorting"""
        
        query = db.query(cls).filter_by(is_deleted=False) if not show_deleted else db.query(cls)

        # Handle sorting
        if order == "desc":
            query = query.order_by(sa.desc(getattr(cls, sort_by)))
        else:
            query = query.order_by(getattr(cls, sort_by))
        
        # Apply search filters
        if search_fields:
            filtered_fields = {field: value for field, value in search_fields.items() if value is not None}
            
            for field, value in filtered_fields.items():
                query = query.filter(getattr(cls, field).ilike(f"%{value}%"))
            
        count = query.count()

        # Handle pagination
        offset = (page - 1) * per_page
        return_val = query, query.offset(offset).limit(per_page).all(), count
        
        if hasattr(cls, "load_properties"):
            cls.load_properties(db, return_val[1])
        return return_val
         
    
    @classmethod
    def fetch_by_id(cls, db: Session, id: str, error_message: Optional[str] = None):
        """Fetches a single instance by ID. (ignores soft-deleted records).\n
        If checking by ID fails, it checks by unique id before then throwing an error if it fails.
        """
        
        query = db.query(cls).filter(
            cls.is_deleted == False,
            sa.or_(
                cls.id == id,
                cls.unique_id == id
            )
        )
        
        obj = query.first()
            
        if obj is None:
            raise HTTPException(status_code=404, detail=error_message or f"Record not found in table `{cls.__tablename__}`")

        if obj is not None and hasattr(cls, "load_properties"):
            cls.load_properties(db, [obj])
            
        return obj
    

    @classmethod
    def fetch_one_by_field(
        cls,
        db: Session,
        throw_error: bool=True,
        error_message: Optional[str] = None,
        status_code: int = 404,
        filter_expr=None,
        **kwargs
    ):
        """
        Fetches one unique record that matches the given field(s).
        Supports complex queries via SQLAlchemy expressions (e.g., or_(), and_()).

        Args:
            db: SQLAlchemy session.
            throw_error: Whether to raise an error if not found.
            error_message: Custom error message.
            status_code: HTTP status code for error.
            filter_expr: Optional SQLAlchemy filter expression (e.g., or_(), and_()).
            **kwargs: Field-based filters (exact match).
        """
        # Always filter out soft-deleted records unless explicitly overridden
        if "is_deleted" not in kwargs and hasattr(cls, "is_deleted"):
            kwargs["is_deleted"] = False

        query = db.query(cls)

        # Apply field-based filters
        if kwargs:
            query = query.filter_by(**kwargs)

        # Apply complex filter expressions if provided
        if filter_expr is not None:
            query = query.filter(filter_expr)

        obj = query.first()
        if obj is None and throw_error:
            raise HTTPException(status_code=status_code, detail=error_message or f"Record not found in table `{cls.__tablename__}`")

        if obj is not None and hasattr(cls, "load_properties"):
            cls.load_properties(db, [obj])
            
        return obj
    
    
    @classmethod
    def fetch_by_field(
        cls,
        db: Session,
        page: Optional[int] = 1,
        per_page: Optional[int] = 10,
        order: str = 'desc',
        sort_by: str = "created_at",
        show_deleted: bool = False,
        search_fields: Optional[Dict[str, Any]] = None,
        ignore_none_kwarg: bool = True,
        paginate: bool = True,
        filter_expr=None,
        **kwargs
    ):
        """
        Fetches all records that match the given field(s), supporting complex SQLAlchemy filter expressions
        such as and_(), or_(), etc. via the filter_expr argument.
        """
        query = db.query(cls)

        # Handle is_deleted logic
        if not show_deleted and hasattr(cls, "is_deleted"):
            query = query.filter(cls.is_deleted == False)

        # Dynamic kwargs filters (exact match)
        if kwargs:
            for field, value in kwargs.items():
                if ignore_none_kwarg and value is None:
                    continue
                if hasattr(cls, field):
                    query = query.filter(getattr(cls, field) == value)

        # Apply complex filter expressions if provided
        if filter_expr is not None:
            query = query.filter(filter_expr)

        # Sorting
        if order == "desc":
            query = query.order_by(sa.desc(getattr(cls, sort_by)))
        else:
            query = query.order_by(getattr(cls, sort_by))

        # Apply search filters
        if search_fields:
            filtered_fields = {field: value for field, value in search_fields.items() if value is not None}
            for field, value in filtered_fields.items():
                query = query.filter(getattr(cls, field).ilike(f"%{value}%"))

        count = query.count()

        # Handle pagination
        offset = (page - 1) * per_page
        if not paginate:
            return_val = query, query.all(), count
        else:
            return_val = query, query.offset(offset).limit(per_page).all(), count

        if hasattr(cls, "load_properties"):
            cls.load_properties(db, return_val[1])

        return return_val

    @classmethod
    def update(cls, db: Session, id: str, commit: bool = True, error_message: Optional[str] = None, **kwargs):
        """Updates an instance with the given ID"""
        
        obj = cls.fetch_by_id(db=db, id=id, error_message=error_message)
        
        for key, value in kwargs.items():
            setattr(obj, key, value)
        
        if commit:
            db.commit()
            db.refresh(obj)
        
        if hasattr(cls, "load_properties"):
            cls.load_properties(db, [obj])
            
        return obj
    

    @classmethod
    def soft_delete(cls, db: Session, id: str, commit: bool = True, error_message: Optional[str] = None):
        """Performs a soft delete by setting is_deleted to True"""
        
        obj = cls.fetch_by_id(db=db, id=id, error_message=error_message)
        obj.is_deleted = True
        if commit:
            db.commit()
    

    @classmethod
    def hard_delete(cls, db: Session, id: str, commit: bool = True, error_message: Optional[str] = None):
        """Permanently deletes an instance by ID or unique_id in case ID fails."""
        
        obj = cls.fetch_by_id(db=db, id=id, error_message=error_message)
        db.delete(obj)
        if commit:
            db.commit()

    
    @classmethod
    def search(
        cls,
        db: Session,
        search_fields: Dict[str, str] = None,
        page: int = 1,
        per_page: int = 10,
        sort_by: str = "created_at",
        order: str = "desc",
        filters: Dict[str, Any] = None,
        ignore_none_filter: bool = True
    ):
        """
        Performs a search on the model based on the provided fields and values.

        :param search_fields: A dictionary where keys are field names and values are search terms.
        :param page: The page number for pagination (default is 1).
        :param per_page: The number of records per page (default is 10).
        :return: A list of matching records.
        """
        
        # Start building the query
        query = db.query(cls)
        
        if filters:
            for field, value in filters.items():
                if ignore_none_filter and value is None:
                    continue
                
                query = query.filter(getattr(cls, field) == value)

        # Apply search filters
        if search_fields:
            filtered_fields = {field: value for field, value in search_fields.items() if value is not None}
            
            for field, value in filtered_fields.items():
                query = query.filter(getattr(cls, field).ilike(f"%{value}%"))

        # Exclude soft-deleted records
        query = query.filter(cls.is_deleted == False)
        
        # Sorting
        if order == "desc":
            query = query.order_by(sa.desc(getattr(cls, sort_by)))
        else:
            query = query.order_by(getattr(cls, sort_by))
            
        count = query.count()

        # Apply pagination
        offset = (page - 1) * per_page
        return_val = query, query.offset(offset).limit(per_page).all(), count

        if hasattr(cls, "load_properties"):
            cls.load_properties(db, return_val[1])

        return return_val
