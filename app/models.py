from datetime import datetime
from typing import Optional
from sqlalchemy import DateTime, create_engine, Column, Integer, String, ForeignKey, Float, func
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel, EmailStr

# Use PostgreSQL without SQLite-specific args
SQLALCHEMY_DATABASE_URL = "postgresql://muriithi:cafeteria@172.17.0.1/myduka"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, nullable=False)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    products = relationship("Product", back_populates="user")

class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, nullable=False)
    name = Column(String, nullable=False)
    cost = Column(Float, nullable=False)
    price = Column(Float, nullable=False)
    stock_quantity = Column(Integer, default=0)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("User", back_populates="products")
    sales = relationship("Sale", back_populates="product")

class Sale(Base):
    __tablename__ = 'sales'
    id = Column(Integer, primary_key=True)
    product_id = Column(Integer, ForeignKey('products.id'), nullable=False)
    stock_quantity = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    product = relationship("Product", back_populates="sales")

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr  
    password: str

class ProductBase(BaseModel):
    name: str
    cost: float
    price: float
    stock_quantity: int

class ProductCreate(ProductBase):
    pass

class UserOut(BaseModel):
    username: str
    email: str

class ProductOut(BaseModel):
    id: int
    name: str
    cost: float
    price: float
    stock_quantity: int

class SalesModel(BaseModel):
    product_id: int
    stock_quantity: int
    created_at: Optional[datetime] = None

class SalesCreate(SalesModel):
    pass

class SalesOut(SalesModel):
    id: int
    user_id: int

def create_tables():
    Base.metadata.create_all(bind=engine)

create_tables()
