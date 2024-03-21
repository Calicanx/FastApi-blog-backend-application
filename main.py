from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from sqlmodel import SQLModel, create_engine, Session, select, Field, Relationship
from pydantic import BaseModel
from typing import Optional, Annotated, List
import uvicorn
import random

app = FastAPI()

SECRET_KEY = "1e070e7e91c1ecf3eecce4d13ae3635392fbe5858308cb3c900ae087aa0b25f1"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

DATABASE_URL = "sqlite:///./database.db"

class UserBase(SQLModel):
    username: str
    email: str
    disabled: bool | None = False

class User(UserBase, table=True):
    hashed_password: str
    id: Optional[int] = Field(default=None, primary_key=True)
    posts: List["Post"] = Relationship(back_populates="user")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str

class PostBase(SQLModel):
    text: str
    class Config:
        max_anystr_length = 1024 * 1024  # 1 MB limit

class Post(PostBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user: User = Relationship(back_populates="posts")
    user_id: int = Field (default=None, foreign_key="user.id")

class UserListWithPosts(UserBase):
    posts: List[Post] = []


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

engine = create_engine(DATABASE_URL)

def get_user_by_username(username: str):
    with Session(engine) as session:
        statement = select(User).where(User.username == username)
        result = session.exec(statement).first()
        return result
    
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp":expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def get_session():
    with Session(engine) as session:
        yield session

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

@app.on_event("startup")
async def on_startup():
    create_db_and_tables()

@app.post("/register", response_model=UserBase)
async def register(*, session: Session = Depends(get_session), user: User):
    user.hashed_password = get_password_hash(user.hashed_password)
    user.id = random.randint(1, 100000)

    user = User.model_validate(user)
    session.add(user)
    session.commit()
    session.refresh(user)

    return user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_username(form_data.username)

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)

    return{"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user

"""
Get user_id from endpoint 'user/me'
Remove id as it is validated and automatically added when you input the text and user_id only
"""
@app.post("/post", response_model=Post)
async def create_post(*, session: Session = Depends(get_session), post: Post, current_user: Annotated [User, Depends(get_current_active_user)]):
    if current_user:
        if len(post.json()) > 1024 * 1024:  # Check if payload size exceeds 1 MB
            raise HTTPException(status_code=413, detail="Payload size exceeds 1 MB")
        with Session(engine) as session:
            session.add(post)
            session.commit()
            session.refresh(post)

        return post
    else:
        raise HTTPException(status_code=401, detail="Not authorized")

@app.get("/posts")
async def read_all_posts(*, session: Session = Depends(get_session), current_user: Annotated[User, Depends(get_current_active_user)], offset: int=0, limit : int=Query(default=100, le=100)):
    if current_user:
        statement = select(Post).offset(offset).limit(limit)
        posts = session.exec(statement).all()
        return posts
    else:
        raise HTTPException(status_code=401, detail="Not authorized")

"""
Get user_id from endpoint 'user/me'
"""
@app.get("/post/{user_id}", response_model=UserListWithPosts)
def read_specific_user_posts(*, session: Session = Depends(get_session), user_id: int, current_user: Annotated[User, Depends(get_current_active_user)]):
        if current_user:
            user = session.get(User, user_id)
            if not user:
                raise HTTPException(status_code=404, detail="Property not found")
            return user
        else:
            raise HTTPException(status_code=401, detail="Not authorized")
        
@app.post("/post/delete/{post_id}")
def delete_post_by_id(*, session: Session = Depends(get_session), post_id: int, current_user: Annotated[User, Depends(get_current_active_user)]):
    if current_user:
        with Session(engine) as session:
            statement = select(Post).where(Post.id == post_id) 
            results = session.exec(statement)  
            post = results.one()
            session.delete(post)
            session.commit()  
            return("Deleted post:", post)
    else:
        raise HTTPException(status_code=401, detail="Not authorized")
         
if __name__ == '__main__':
    uvicorn(app, host = '127.0.0.1', port = 8000)