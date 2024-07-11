from typing import Dict, List
from fastapi import FastAPI, Depends, HTTPException,Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from sqlalchemy import func
from sqlalchemy.orm import Session
from models import (
    Sale,
    SalesCreate,
    SessionLocal,
    User,
    Product,
    UserCreate,
    UserLogin,
    ProductCreate,
)
import sentry_sdk


sentry_sdk.init(
    dsn="https://e96d672d218c98a1ac35361b36f91f71@o4507329770749952.ingest.us.sentry.io/4507329776451584",
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for performance monitoring.
    traces_sample_rate=1.0,
    # Set profiles_sample_rate to 1.0 to profile 100%
    # of sampled transactions.
    # We recommend adjusting this value in production.
    profiles_sample_rate=1.0,
)



app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],  
)

db = SessionLocal()

SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_user(email: str):
    db_user = db.query(User).filter(User.email == email).first()
    return db_user



def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user or not verify_password(password, user.password):
        return False
    return user



def create_accessToken(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_token_auth_header(
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
):
    if credentials.scheme != "Bearer":
        raise HTTPException(status_code=403, detail="Invalid authentication scheme")
    return credentials.credentials


def get_current_user(token: str = Depends(get_token_auth_header)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Could not validate credentials"
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = get_user(username)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

@app.get('/')
def index():
    return{"message": "I LOVE football"}

@app.get("/sentry-deb")
async def trigger_error():
    division_by_zero = 1 / 0

@app.post("/register")
def register(user: UserCreate):

    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = pwd_context.hash(user.password)
    new_user = User(username=user.username, email=user.email, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"username": new_user.username, "email": new_user.email} 


@app.post("/login")
def login(user: UserLogin):
    db_user = authenticate_user(user.email, user.password)
    if not db_user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    accessToken = create_accessToken(
        data={"sub": db_user.email}, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"accessToken": accessToken, "token_type": "bearer"}


@app.get("/products")
def get_products(current_user: User = Depends(get_current_user)):
    products = db.query(Product).filter(Product.user_id == current_user.id).all()
    return products


@app.post("/products")
def create_product(product: ProductCreate, current_user: User = Depends(get_current_user)):
    db_product = Product(**product.dict(), user_id=current_user.id)
    db.add(db_product)
    db.commit()
    db.refresh(db_product)
    return db_product

@app.get("/sales")
def get_sales(current_user: User = Depends(get_current_user)):
    sales = db.query(Sale).filter(Sale.user_id == current_user.id).all()
    return sales

@app.post("/sales")
def create_sales(sale: SalesCreate, current_user: User = Depends(get_current_user)):
    db_sale = Sale(**sale.dict(), user_id=current_user.id)
    db.add(db_sale)
    db.commit()
    db.refresh(db_sale)
    return db_sale


@app.get("/dashboard")
def dashboard(current_user: User = Depends(get_current_user)):
    try:
        sales_per_day = (
            db.query(
                func.date(Sale.created_at).label("date"),
                func.sum(Sale.stock_quantity * Product.price).label("total_sales"),
            )
            .join(Product)
            .group_by(func.date(Sale.created_at))
            .filter(Sale.user_id == current_user.id)
            .all()
        )

        sales_data = [
            {"date": str(day), "total_sales": sales} for day, sales in sales_per_day
        ]

        sales_per_product = (
            db.query(
                Product.name,
                func.sum(Sale.stock_quantity * Product.price).label("sales_product"),
            )
            .join(Sale)
            .group_by(Product.name)
            .filter(Sale.user_id == current_user.id)
            .all()
        )

        salesproduct_data = [
            {"name": name, "sales_product": sales_product}
            for name, sales_product in sales_per_product
        ]

        return {"sales_data": sales_data, "salesproduct_data": salesproduct_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/users")
def get_all_users():
    users = db.query(User).all()
    return users
