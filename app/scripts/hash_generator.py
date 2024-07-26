from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
plain_password = "7727"
hashed_password = pwd_context.hash(plain_password)
print(hashed_password)
