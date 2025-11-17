from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse, Response
from starlette.middleware.cors import CORSMiddleware

from dotenv import load_dotenv
from pathlib import Path
import os
import json
import uuid
import jwt
import bcrypt
import logging
import io
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

# Mongo (Async)
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING

# Firebase
import firebase_admin
from firebase_admin import credentials, storage

# PDF
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

# Load ENV
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

# ======================
#  MongoDB Connection
# ======================
MONGO_URL = os.environ.get("MONGO_URL", "")
DB_NAME = os.environ.get("DB_NAME", "pavanputra_db")

db = None
try:
    mongo_client = AsyncIOMotorClient(MONGO_URL)
    db = mongo_client[DB_NAME]
    print("✅ MongoDB Connected")
except Exception as e:
    print("❌ MongoDB Error:", e)

# ======================
#  Firebase Initialization
# ======================
try:
    FIREBASE_CONFIG = os.environ.get("FIREBASE_CONFIG", "{}")
    config = json.loads(FIREBASE_CONFIG)

    if config.get("private_key") and not firebase_admin._apps:
        cred = credentials.Certificate(config)
        firebase_admin.initialize_app(
            cred,
            {
                "storageBucket": os.environ.get(
                    "FIREBASE_STORAGE_BUCKET",
                    "pavanputra-88fda.appspot.com"
                )
            }
        )
        print("✅ Firebase Initialized")
    else:
        print("⚠️ Firebase config missing or incomplete")

except Exception as e:
    print("❌ Firebase Error:", e)

# ======================
#     FastAPI App
# ======================
app = FastAPI(title="Pavanputra Mega Mart API", version="1.0")
api = APIRouter(prefix="/api")
security = HTTPBearer()

# ======================
#        CORS
# ======================
frontend_origins = [
    "https://pmm-for-frontend.vercel.app",
    "https://pavanputramegamart.in",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=frontend_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

JWT_SECRET = os.environ.get("JWT_SECRET", "pavanputra-secret-2025")
JWT_ALGO = "HS256"

# ======================
#   Helper Functions
# ======================

def create_token(data: dict):
    data.update({
        "exp": datetime.now(timezone.utc) + timedelta(days=7)
    })
    return jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGO)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload
    except:
        raise HTTPException(401, "Invalid or expired token")

def hash_password(pwd: str):
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()

def verify_password(raw: str, hashed: str):
    return bcrypt.checkpw(raw.encode(), hashed.encode())
  
from pydantic import BaseModel, Field

# ---------- AUTH MODELS ----------
class UserLogin(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    password: str
    role: str        # "admin" or "delivery"
    full_name: str
    mobile: str | None = None


# ---------- CATEGORY MODEL ----------
class Category(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    name_gu: str
    image_urls: List[str] = []
    order: int = 0
    is_visible: bool = True
    visible_to_users: List[str] = []
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------- PRODUCT MODEL ----------
class Product(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    name_gu: str
    category_id: str
    price: float
    mrp: float = 0
    unit: str
    discount: float = 0
    image_url: str
    images: List[str] = []
    description: str = ""
    description_gu: str = ""
    stock: int = 0
    rating: float = 4.5
    delivery_time: str = "10 mins"
    is_active: bool = True
    is_on_hold: bool = False
    is_out_of_stock: bool = False

    # Bulk Packaging
    bulk_package_size: float = 0
    bulk_package_unit: str = ""
    small_package_size: float = 0
    small_package_unit: str = ""
    small_packages_per_bulk: int = 0

    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def calculate_discount(self):
        if self.mrp > 0 and self.price < self.mrp:
            self.discount = round(((self.mrp - self.price) / self.mrp) * 100)
        else:
            self.discount = 0


# ---------- CUSTOMER ----------
class Customer(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    shop_name: str | None = None
    owner_name: str | None = None
    mobile: str
    address: str | None = None
    pincode: str | None = None
    location: Dict[str, float] = {}
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------- ORDER ITEM ----------
class OrderItem(BaseModel):
    product_id: str
    product_name: str
    quantity: int
    unit: str
    price: float
    discount: float = 0


# ---------- ORDER ----------
class Order(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    customer_id: str
    customer_info: Dict[str, Any] = {}
    items: List[OrderItem]
    total_amount: float
    status: str = "pending"
    delivery_partner_id: str | None = None
    delivery_partner_name: str | None = None
    delivery_otp: str | None = None
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    delivered_at: str | None = None


# ---------- SETTINGS ----------
class Settings(BaseModel):
    logo_url: str = ""
    tagline: str = "Tamara Vyapar no Sacho Sathi"
    tagline_gu: str = "તમારા વ્યવસાય નો સાચો સાથી"
    primary_color: str = "#84CC16"
    secondary_color: str = "#FBBF24"
    google_maps_key: str = ""
    banners: List[str] = []

    # Delivery
    delivery_enabled: bool = True
    delivery_days: List[str] = [
        "Monday", "Tuesday", "Wednesday",
        "Thursday", "Friday", "Saturday", "Sunday"
    ]
    delivery_time_slots: List[Dict[str, str]] = [
        {"start": "09:00", "end": "12:00", "label": "Morning"},
        {"start": "12:00", "end": "15:00", "label": "Afternoon"},
        {"start": "15:00", "end": "18:00", "label": "Evening"},
        {"start": "18:00", "end": "21:00", "label": "Night"},
    ]
    delivery_pincodes: List[str] = []
    delivery_areas: List[str] = []

import random   # ✅ ADD THIS (important for OTP + delivery OTP)

# --------------------------
#      AUTH ROUTES
# --------------------------
@api.post("/auth/login")
async def login(user: UserLogin):
    if db is None:
        raise HTTPException(500, "Database not available")

    user_doc = await db.users.find_one({"username": user.username})
    if not user_doc:
        raise HTTPException(401, "Invalid username or password")

    if not verify_password(user.password, user_doc["password"]):
        raise HTTPException(401, "Invalid username or password")

    token = create_token({
        "user_id": user_doc["id"],
        "username": user_doc["username"],
        "role": user_doc["role"],
    })

    return {
        "token": token,
        "user": {
            "id": user_doc["id"],
            "username": user_doc["username"],
            "role": user_doc["role"],
            "full_name": user_doc.get("full_name", "")
        }
    }


@api.post("/auth/register")
async def register(user: UserRegister, current=Depends(verify_token)):
    if current["role"] != "admin":
        raise HTTPException(403, "Only admin can add users")

    exists = await db.users.find_one({"username": user.username})
    if exists:
        raise HTTPException(400, "Username already exists")

    user_data = {
        "id": str(uuid.uuid4()),
        "username": user.username,
        "password": hash_password(user.password),
        "role": user.role,
        "full_name": user.full_name,
        "mobile": user.mobile,
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    await db.users.insert_one(user_data)
    return {"message": "User registered successfully"}


# --------------------------
#      OTP LOGIN ROUTES
# --------------------------
otp_store = {}


@api.post("/send-otp")
async def send_otp(data: dict):
    mobile = data.get("mobile")

    if not mobile or len(mobile) != 10:
        raise HTTPException(400, "Invalid mobile number")

    otp = str(random.randint(100000, 999999))    # uses random (required)
    otp_store[mobile] = {
        "otp": otp,
        "expires": datetime.now(timezone.utc) + timedelta(minutes=5)
    }

    print(f"📱 OTP for {mobile}: {otp}")
    return {"message": "OTP sent", "otp": otp}


@api.post("/verify-otp")
async def verify_otp(data: dict):
    mobile = data.get("mobile")
    otp = data.get("otp")

    if mobile not in otp_store:
        raise HTTPException(400, "OTP expired or not found")

    record = otp_store[mobile]
    if datetime.now(timezone.utc) > record["expires"]:
        del otp_store[mobile]
        raise HTTPException(400, "OTP expired")

    if record["otp"] != otp:
        raise HTTPException(400, "Invalid OTP")

    del otp_store[mobile]

    customer = await db.customers.find_one({"mobile": mobile})
    if not customer:
        customer_data = {
            "id": str(uuid.uuid4()),
            "mobile": mobile,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.customers.insert_one(customer_data)
        customer = customer_data

    customer.pop("_id", None)

    token = jwt.encode({
        "user_id": customer["id"],
        "mobile": mobile,
        "role": "customer",
        "exp": datetime.now(timezone.utc) + timedelta(days=30)
    }, JWT_SECRET, algorithm=JWT_ALGO)

    return {
        "message": "Login successful",
        "token": token,
        "customer": customer
    }


# --------------------------
#     CATEGORY ROUTES
# --------------------------
@api.get("/categories")
async def get_categories():
    if db is None:
        return []

    categories = []
    async for c in db.categories.find().sort("order", ASCENDING):
        c.pop("_id", None)
        categories.append(c)

    return categories


@api.post("/categories")
async def create_category(cat: Category, current=Depends(verify_token)):
    if current["role"] != "admin":
        raise HTTPException(403, "Admin only")

    await db.categories.insert_one(cat.model_dump())
    return cat


@api.put("/categories/{cid}")
async def update_category(cid: str, cat: Category, current=Depends(verify_token)):
    if current["role"] != "admin":
        raise HTTPException(403, "Admin only")

    await db.categories.update_one({"id": cid}, {"$set": cat.model_dump()})
    return cat


@api.delete("/categories/{cid}")
async def delete_category(cid: str, current=Depends(verify_token)):
    if current["role"] != "admin":
        raise HTTPException(403, "Admin only")

    await db.categories.delete_one({"id": cid})
    return {"message": "Category deleted"}


# --------------------------
#     PRODUCT ROUTES
# --------------------------
@api.get("/products")
async def get_products(category_id: str | None = None):
    query = {"is_active": True}
    if category_id:
        query["category_id"] = category_id

    products = []
    async for p in db.products.find(query):
        p.pop("_id", None)
        products.append(p)

    return products


@api.post("/products")
async def create_product(p: Product, current=Depends(verify_token)):
    if current["role"] != "admin":
        raise HTTPException(403, "Admin only")

    p.calculate_discount()
    await db.products.insert_one(p.model_dump())
    return p


@api.put("/products/{pid}")
async def update_product(pid: str, p: Product, current=Depends(verify_token)):
    if current["role"] != "admin":
        raise HTTPException(403, "Admin only")

    p.calculate_discount()
    await db.products.update_one({"id": pid}, {"$set": p.model_dump()})
    return p


@api.delete("/products/{pid}")
async def delete_product(pid: str, current=Depends(verify_token)):
    if current["role"] != "admin":
        raise HTTPException(403, "Admin only")

    await db.products.delete_one({"id": pid})
    return {"message": "Product deleted"}


# --------------------------
#  PRODUCT STATUS MANAGEMENT
# --------------------------
@api.put("/products/{pid}/hold")
async def hold_product(pid: str, current=Depends(verify_token)):
    if current["role"] != "admin":
        raise HTTPException(403, "Admin only")

    await db.products.update_one(
        {"id": pid},
        {"$set": {"is_active": False, "is_on_hold": True}}
    )
    return {"message": "Product on hold"}


@api.put("/products/{pid}/out-of-stock")
async def out_of_stock(pid: str, current=Depends(verify_token)):
    if current["role"] != "admin":
        raise HTTPException(403, "Admin only")

    await db.products.update_one(
        {"id": pid},
        {"$set": {"is_out_of_stock": True, "stock": 0}}
    )
    return {"message": "Product marked out of stock"}


@api.put("/products/{pid}/activate")
async def activate_product(pid: str, current=Depends(verify_token)):
    if current["role"] != "admin":
        raise HTTPException(403, "Admin only")

    await db.products.update_one(
        {"id": pid},
        {"$set": {"is_active": True, "is_on_hold": False, "is_out_of_stock": False}}
    )
    return {"message": "Product activated"}

# --------------------------
#        CREATE ORDER
# --------------------------
@api.post("/orders")
async def create_order(order: Order):
    if db is None:
        raise HTTPException(500, "DB not ready")

    # generate OTP
    order.delivery_otp = str(random.randint(1000, 9999))

    # validation
    if not order.items:
        raise HTTPException(400, "Order must contain items")

    if order.total_amount <= 0:
        raise HTTPException(400, "Invalid total amount")

    # stock check + deduct
    for item in order.items:
        product = await db.products.find_one({"id": item.product_id})

        if not product:
            raise HTTPException(404, f"Product not found: {item.product_name}")

        if product.get("stock", 0) < item.quantity:
            raise HTTPException(
                400, f"Insufficient stock for {item.product_name}"
            )

        await db.products.update_one(
            {"id": item.product_id},
            {"$set": {"stock": product["stock"] - item.quantity}}
        )

    await db.orders.insert_one(order.model_dump())

    return {
        "message": "Order placed",
        "order_id": order.id,
        "delivery_otp": order.delivery_otp
    }


# --------------------------
#      GET ORDERS (ADMIN)
# --------------------------
@api.get("/orders")
async def get_orders(status: str | None = None, current=Depends(verify_token)):
    query = {}
    if status:
        query["status"] = status

    # delivery partner
    if current["role"] == "delivery":
        query["delivery_partner_id"] = current["user_id"]

    result = []
    async for o in db.orders.find(query).sort("created_at", DESCENDING):
        o.pop("_id", None)
        result.append(o)

    return result


# --------------------------
#      ORDER STATUS UPDATE
# --------------------------
@api.put("/orders/{oid}/status")
async def update_status(oid: str, data: dict, current=Depends(verify_token)):
    await db.orders.update_one(
        {"id": oid},
        {"$set": {"status": data["status"]}}
    )
    return {"message": "Status updated"}


# --------------------------
#      ASSIGN DELIVERY PARTNER
# --------------------------
@api.put("/orders/{oid}/assign")
async def assign_delivery(oid: str, data: dict, current=Depends(verify_token)):
    if current["role"] != "admin":
        raise HTTPException(403, "Admin only")

    await db.orders.update_one(
        {"id": oid},
        {"$set": {
            "delivery_partner_id": data["delivery_partner_id"],
            "delivery_partner_name": data["delivery_partner_name"]
        }}
    )
    return {"message": "Assigned to partner"}


# --------------------------
#   DELIVERY OTP VERIFY
# --------------------------
@api.post("/orders/{oid}/verify-delivery-otp")
async def verify_delivery_otp(oid: str, data: dict, current=Depends(verify_token)):
    if current["role"] != "delivery":
        raise HTTPException(403, "Delivery only")

    order = await db.orders.find_one({"id": oid})
    if not order:
        raise HTTPException(404, "Order not found")

    if order["delivery_otp"] != data["otp"]:
        raise HTTPException(400, "Invalid OTP")

    await db.orders.update_one(
        {"id": oid},
        {"$set": {
            "status": "delivered",
            "delivered_at": datetime.now(timezone.utc).isoformat()
        }}
    )

    return {"message": "Order delivered"}


# --------------------------
#       DELIVERY PARTNERS LIST
# --------------------------
@api.get("/delivery-partners")
async def get_delivery_partners(current=Depends(verify_token)):
    if current["role"] != "admin":
        raise HTTPException(403, "Admin only")

    partners = []
    async for u in db.users.find({"role": "delivery"}):
        u.pop("_id", None)
        partners.append(u)
    return partners


# --------------------------
#      DASHBOARD STATS
# --------------------------
@api.get("/dashboard/stats")
async def dashboard(current=Depends(verify_token)):
    if current["role"] != "admin":
        raise HTTPException(403, "Admin only")

    all_orders = []
    async for o in db.orders.find():
        all_orders.append(o)

    total_orders = len(all_orders)
    delivered = len([o for o in all_orders if o["status"] == "delivered"])
    pending = len([o for o in all_orders if o["status"] == "pending"])
    total_sales = sum(o["total_amount"] for o in all_orders if o["status"] == "delivered")

    low_stock = await db.products.count_documents({"stock": {"$lt": 10}})

    return {
        "total_orders": total_orders,
        "pending_orders": pending,
        "delivered_orders": delivered,
        "total_sales": total_sales,
        "low_stock_products": low_stock
    }


# --------------------------
#          SEARCH
# --------------------------
@api.get("/search")
async def search(q: str = ""):
    if not q:
        return []

    result = []
    async for p in db.products.find({
        "is_active": True,
        "$or": [
            {"name": {"$regex": q, "$options": "i"}},
            {"name_gu": {"$regex": q, "$options": "i"}},
        ]
    }).limit(20):
        p.pop("_id", None)
        result.append(p)

    return result


# --------------------------
#     IMAGE UPLOAD (Firebase)
# --------------------------
@api.post("/upload-image")
async def upload_image(file: UploadFile = File(...), current=Depends(verify_token)):
    if current["role"] != "admin":
        raise HTTPException(403, "Admin only")

    contents = await file.read()
    ext = file.filename.split(".")[-1]
    filename = f"products/{uuid.uuid4()}.{ext}"

    bucket = storage.bucket()
    blob = bucket.blob(filename)
    blob.upload_from_string(contents, content_type=file.content_type)
    blob.make_public()

    return {"url": blob.public_url, "filename": filename}


# --------------------------
#      INVOICE GENERATION
# --------------------------
@api.get("/invoice/{oid}")
async def invoice_pdf(oid: str):
    order = await db.orders.find_one({"id": oid})
    if not order:
        raise HTTPException(404, "Order not found")

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawCentredString(width/2, height - 50, "INVOICE")

    y = height - 100
    pdf.setFont("Helvetica", 12)
    pdf.drawString(40, y, f"Order ID: {order['id'][:8]}")
    y -= 20
    pdf.drawString(40, y, f"Date: {order['created_at'][:10]}")

    y -= 40
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(40, y, "Items:")
    y -= 30
    pdf.setFont("Helvetica", 10)

    for item in order["items"]:
        pdf.drawString(40, y, f"{item['product_name']}  x{item['quantity']}  ₹{item['price']}")
        y -= 18

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(40, y - 20, f"Total Amount: ₹{order['total_amount']}")
    pdf.save()

    buffer.seek(0)
    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=invoice.pdf"}
    )


# --------------------------
#       INCLUDE ROUTER
# --------------------------
app.include_router(api)


# --------------------------
#      UVICORN RUN (LOCAL)
# --------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000)),
        reload=True
    )
