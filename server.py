from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse, Response
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
import uuid
import jwt
import bcrypt
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING
import json
import firebase_admin
from firebase_admin import credentials, storage
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import io
import random

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
DB_NAME = os.environ.get('DB_NAME', 'pavanputra_db')

# Initialize MongoDB client
try:
    mongo_client = AsyncIOMotorClient(MONGO_URL)
    db = mongo_client[DB_NAME]
    print(f"✅ MongoDB connected successfully to {DB_NAME}")
except Exception as e:
    print(f"❌ MongoDB connection error: {e}")
    db = None

# Initialize Firebase Admin SDK
try:
    firebase_config_str = os.environ.get('FIREBASE_CONFIG', '{}')
    firebase_config = json.loads(firebase_config_str)
    
    if firebase_config.get('private_key') and not firebase_admin._apps:
        cred = credentials.Certificate(firebase_config)
        firebase_admin.initialize_app(cred, {
            'storageBucket': os.environ.get('FIREBASE_STORAGE_BUCKET', 'pavanputra-88fda.firebasestorage.app')
        })
        print(f"✅ Firebase initialized successfully")
    else:
        print("⚠️ Firebase credentials incomplete")
except Exception as e:
    print(f"❌ Firebase initialization error: {e}")

app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

JWT_SECRET = os.environ.get('JWT_SECRET', 'pavanputra-secret-key-2025')
JWT_ALGORITHM = 'HS256'

# ============ MODELS ============

class UserLogin(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    password: str
    role: str  # admin or delivery
    full_name: str
    mobile: Optional[str] = None

class Category(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    name_gu: str  # Gujarati name
    image_urls: List[str] = []  # 4 product images
    order: int = 0
    is_visible: bool = True  # Visibility control
    visible_to_users: List[str] = []  # Empty = visible to all, or specific user IDs
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class Product(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    name_gu: str
    category_id: str
    price: float  # Sell price
    mrp: float = 0  # Maximum Retail Price
    unit: str  # Kg, Gram, Piece, Box
    discount: float = 0  # Auto-calculated from MRP and price
    image_url: str
    images: List[str] = []  # Multiple product images
    description: str = ""
    description_gu: str = ""
    stock: int = 0
    rating: float = 4.5
    delivery_time: str = "10 mins"
    is_active: bool = True
    is_on_hold: bool = False  # Hold status
    is_out_of_stock: bool = False  # Out of stock status
    # Bulk packaging logic
    bulk_package_size: float = 0  # e.g., 30 (for 30kg pack)
    bulk_package_unit: str = ""  # e.g., "Kg"
    small_package_size: float = 0  # e.g., 1 (for 1kg packet)
    small_package_unit: str = ""  # e.g., "Kg"
    small_packages_per_bulk: int = 0  # e.g., 30 (30 packets of 1kg in 30kg pack)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    def calculate_discount(self):
        """Auto-calculate discount percentage from MRP and price"""
        if self.mrp > 0 and self.price < self.mrp:
            self.discount = round(((self.mrp - self.price) / self.mrp) * 100)  # Round to nearest whole number
        else:
            self.discount = 0

class Customer(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    shop_name: str
    owner_name: str
    mobile: str
    address: str
    pincode: str
    location: Dict[str, float] = {}  # {lat, lng}
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class OrderItem(BaseModel):
    product_id: str
    product_name: str
    quantity: int
    unit: str
    price: float
    discount: float = 0

class Order(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    customer_id: str
    customer_info: Dict[str, Any] = {}
    items: List[OrderItem] = []
    total_amount: float
    status: str = "pending"  # pending, packed, out_for_delivery, delivered
    delivery_partner_id: Optional[str] = None
    delivery_partner_name: Optional[str] = None
    delivery_otp: Optional[str] = None  # 4-digit OTP for delivery verification
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    delivered_at: Optional[str] = None

class Settings(BaseModel):
    logo_url: str = ""
    tagline: str = "Tamara Vyapar no Sacho Sathi"
    tagline_gu: str = "તમારા વ્યાપાર નો સાચો સાથી"
    primary_color: str = "#84CC16"  # Light green (lime-500)
    secondary_color: str = "#FBBF24"  # Yellow (amber-400)
    google_maps_key: str = ""
    banners: List[str] = []  # Homepage banner images (max 10)
    
    # Delivery Settings
    delivery_enabled: bool = True
    delivery_days: List[str] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    delivery_time_slots: List[Dict[str, str]] = [
        {"start": "09:00", "end": "12:00", "label": "Morning (9 AM - 12 PM)"},
        {"start": "12:00", "end": "15:00", "label": "Afternoon (12 PM - 3 PM)"},
        {"start": "15:00", "end": "18:00", "label": "Evening (3 PM - 6 PM)"},
        {"start": "18:00", "end": "21:00", "label": "Night (6 PM - 9 PM)"}
    ]
    delivery_pincodes: List[str] = []  # Allowed pincodes for delivery
    delivery_areas: List[str] = []  # Allowed area names for delivery

# ============ AUTH HELPERS ============

def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except:
        raise HTTPException(status_code=401, detail="Invalid authentication")

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))

# ============ ROUTES ============

@api_router.get("/")
async def root():
    return {"message": "Pavanputra Mega Mart API", "version": "1.0"}

# AUTH
@api_router.post("/auth/login")
async def login(user: UserLogin):
    if db is None:
        raise HTTPException(500, "Database not available")
    
    try:
        user_doc = await db.users.find_one({'username': user.username})
        
        if not user_doc or not verify_password(user.password, user_doc['password']):
            raise HTTPException(401, "Invalid credentials")
        
        token = create_token({
            "user_id": user_doc['id'],
            "username": user_doc['username'],
            "role": user_doc['role']
        })
        
        return {
            "token": token,
            "user": {
                "id": user_doc['id'],
                "username": user_doc['username'],
                "role": user_doc['role'],
                "full_name": user_doc.get('full_name', '')
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {e}")
        raise HTTPException(500, "Login failed")

@api_router.post("/auth/register")
async def register(user: UserRegister, current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Only admins can register users")
    
    if db is None:
        raise HTTPException(500, "Database not available")
    
    try:
        # Check if username exists
        existing = await db.users.find_one({'username': user.username})
        if existing:
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
        return {"message": "User registered successfully", "user_id": user_data['id']}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Register error: {e}")
        raise HTTPException(500, "Registration failed")

# CATEGORIES
@api_router.get("/categories")
async def get_categories():
    try:
        if db is None:
            return await get_demo_categories()
        
        categories_list = []
        async for doc in db.categories.find().sort('order', ASCENDING):
            doc.pop('_id', None)
            categories_list.append(doc)
        
        if not categories_list:
            return await get_demo_categories()
        
        return categories_list
    except Exception as e:
        print(f"Error loading categories: {e}")
        return await get_demo_categories()

@api_router.post("/categories")
async def create_category(category: Category, current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        category_data = category.model_dump()
        await db.categories.insert_one(category_data)
        return category
    except Exception as e:
        print(f"Create category error: {e}")
        raise HTTPException(500, "Failed to create category")

@api_router.put("/categories/{category_id}")
async def update_category(category_id: str, category: Category, current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        category_data = category.model_dump()
        await db.categories.update_one({'id': category_id}, {'$set': category_data})
        return category
    except Exception as e:
        print(f"Update category error: {e}")
        raise HTTPException(500, "Failed to update category")

@api_router.delete("/categories/{category_id}")
async def delete_category(category_id: str, current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        await db.categories.delete_one({'id': category_id})
        return {"message": "Category deleted"}
    except Exception as e:
        print(f"Delete category error: {e}")
        raise HTTPException(500, "Failed to delete category")

# PRODUCTS
@api_router.get("/products")
async def get_products(category_id: Optional[str] = None):
    try:
        if db is None:
            return await get_demo_products(category_id)
        
        query = {'is_active': True}
        if category_id:
            query['category_id'] = category_id
        
        products_list = []
        async for doc in db.products.find(query):
            doc.pop('_id', None)
            products_list.append(doc)
        
        if not products_list:
            return await get_demo_products(category_id)
        
        return products_list
    except Exception as e:
        print(f"Error loading products: {e}")
        return await get_demo_products(category_id)

@api_router.post("/products")
async def create_product(product: Product, current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        # Auto-calculate discount from MRP and selling price
        product.calculate_discount()
        
        product_data = product.model_dump()
        await db.products.insert_one(product_data)
        return product
    except Exception as e:
        print(f"Create product error: {e}")
        raise HTTPException(500, "Failed to create product")

@api_router.put("/products/{product_id}")
async def update_product(product_id: str, product: Product, current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        # Auto-calculate discount from MRP and selling price
        product.calculate_discount()
        
        product_data = product.model_dump()
        await db.products.update_one({'id': product_id}, {'$set': product_data})
        return product
    except Exception as e:
        print(f"Update product error: {e}")
        raise HTTPException(500, "Failed to update product")

@api_router.delete("/products/{product_id}")
async def delete_product(product_id: str, current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        await db.products.delete_one({'id': product_id})
        return {"message": "Product deleted permanently"}
    except Exception as e:
        print(f"Delete product error: {e}")
        raise HTTPException(500, "Failed to delete product")

# PRODUCT STATUS MANAGEMENT
@api_router.put("/products/{product_id}/hold")
async def hold_product(product_id: str, current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        await db.products.update_one({'id': product_id}, {'$set': {'is_on_hold': True, 'is_active': False}})
        return {"message": "Product put on hold"}
    except Exception as e:
        print(f"Hold product error: {e}")
        raise HTTPException(500, "Failed to hold product")

@api_router.put("/products/{product_id}/out-of-stock")
async def mark_out_of_stock(product_id: str, current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        await db.products.update_one({'id': product_id}, {'$set': {'is_out_of_stock': True, 'stock': 0}})
        return {"message": "Product marked as out of stock"}
    except Exception as e:
        print(f"Mark out of stock error: {e}")
        raise HTTPException(500, "Failed to mark product out of stock")

@api_router.put("/products/{product_id}/activate")
async def activate_product(product_id: str, current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        await db.products.update_one({'id': product_id}, {'$set': {'is_active': True, 'is_on_hold': False, 'is_out_of_stock': False}})
        return {"message": "Product activated"}
    except Exception as e:
        print(f"Activate product error: {e}")
        raise HTTPException(500, "Failed to activate product")

# MOBILE OTP LOGIN SYSTEM
otp_store = {}  # In-memory OTP store (format: {mobile: {otp: code, expires: timestamp}})

@api_router.post("/send-otp")
async def send_otp(data: dict):
    mobile = data.get('mobile')
    if not mobile or len(mobile) != 10:
        raise HTTPException(400, "Invalid mobile number")
    
    # Generate 6-digit OTP
    import random
    otp = str(random.randint(100000, 999999))
    
    # Store OTP with 5 minute expiry
    from datetime import timedelta
    otp_store[mobile] = {
        'otp': otp,
        'expires': datetime.now(timezone.utc) + timedelta(minutes=5)
    }
    
    # In production, send SMS here
    print(f"📱 OTP for {mobile}: {otp}")
    
    return {"message": "OTP sent successfully", "otp": otp}  # Remove otp in production

@api_router.post("/verify-otp")
async def verify_otp(data: dict):
    mobile = data.get('mobile')
    otp = data.get('otp')
    
    if not mobile or not otp:
        raise HTTPException(400, "Mobile and OTP required")
    
    # Check if OTP exists and not expired
    if mobile not in otp_store:
        raise HTTPException(400, "OTP not found or expired")
    
    stored = otp_store[mobile]
    if datetime.now(timezone.utc) > stored['expires']:
        del otp_store[mobile]
        raise HTTPException(400, "OTP expired")
    
    if stored['otp'] != otp:
        raise HTTPException(400, "Invalid OTP")
    
    # OTP verified, remove from store
    del otp_store[mobile]
    
    # Check if customer exists, if not create
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    customer = await db.customers.find_one({'mobile': mobile})
    
    if not customer:
        # Create new customer
        customer_data = {
            'id': str(uuid.uuid4()),
            'mobile': mobile,
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        await db.customers.insert_one(customer_data)
        customer = customer_data
    
    customer.pop('_id', None)
    
    # Generate JWT token
    token_data = {
        'user_id': customer['id'],
        'mobile': mobile,
        'role': 'customer',
        'exp': datetime.now(timezone.utc) + timedelta(days=30)
    }
    token = jwt.encode(token_data, JWT_SECRET, algorithm='HS256')
    
    return {
        "token": token,
        "customer": customer,
        "message": "Login successful"
    }
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        customer_data = customer.model_dump()
        await db.customers.insert_one(customer_data)
        return customer
    except Exception as e:
        print(f"Create customer error: {e}")
        raise HTTPException(500, "Failed to create customer")

@api_router.get("/customers/{mobile}")
async def get_customer_by_mobile(mobile: str):
    if db is None:
        return None
    
    try:
        customer_doc = await db.customers.find_one({'mobile': mobile})
        if customer_doc:
            customer_doc.pop('_id', None)
            return customer_doc
        return None
    except Exception as e:
        print(f"Get customer error: {e}")
        return None

# ORDERS
@api_router.post("/orders")
async def create_order(order: Order):
    """
    Create a new order with comprehensive error handling and validation
    """
    if db is None:
        raise HTTPException(status_code=500, detail="Database not initialized")
    
    try:
        # Generate 4-digit delivery OTP
        import random
        order.delivery_otp = str(random.randint(1000, 9999))
        
        # Validate order data
        if not order.items or len(order.items) == 0:
            raise HTTPException(status_code=400, detail="Order must contain at least one item")
        
        if order.total_amount <= 0:
            raise HTTPException(status_code=400, detail="Order total must be greater than zero")
        
        if not order.customer_id:
            raise HTTPException(status_code=400, detail="Customer ID is required")
        
        # Validate and deduct stock for each product
        for item in order.items:
            if item.quantity <= 0:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Invalid quantity for product {item.product_name}"
                )
            
            product = await db.products.find_one({'id': item.product_id})
            
            if not product:
                raise HTTPException(
                    status_code=404, 
                    detail=f"Product not found: {item.product_name}"
                )
            
            if product.get('status') == 'inactive':
                raise HTTPException(
                    status_code=400, 
                    detail=f"Product not available: {item.product_name}"
                )
            
            # Check stock availability
            current_stock = product.get('stock', 0)
            if current_stock < item.quantity:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Insufficient stock for {item.product_name}. Available: {current_stock}, Requested: {item.quantity}"
                )
            
            # Deduct stock
            new_stock = current_stock - item.quantity
            update_result = await db.products.update_one(
                {'id': item.product_id}, 
                {'$set': {'stock': new_stock}}
            )
            
            if update_result.modified_count == 0:
                # Rollback might be needed here, but for now log the error
                print(f"Warning: Failed to update stock for product {item.product_id}")
        
        # Insert order into database
        order_data = order.model_dump()
        insert_result = await db.orders.insert_one(order_data)
        
        if not insert_result.inserted_id:
            raise HTTPException(status_code=500, detail="Failed to save order to database")
        
        print(f"✅ Order created successfully: {order.id}")
        return {
            "success": True,
            "message": "Order placed successfully",
            "order": order
        }
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        # Log unexpected errors
        print(f"❌ Unexpected error creating order: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to create order: {str(e)}"
        )

@api_router.get("/orders")
async def get_orders(status: Optional[str] = None, current_user: dict = Depends(verify_token)):
    if db is None:
        return []
    
    try:
        query = {}
        
        if status:
            query['status'] = status
        
        # Filter by delivery partner if delivery role
        if current_user['role'] == 'delivery':
            query['delivery_partner_id'] = current_user['user_id']
        
        orders_list = []
        async for doc in db.orders.find(query).sort('created_at', DESCENDING):
            doc.pop('_id', None)
            orders_list.append(doc)
        
        return orders_list
    except Exception as e:
        print(f"Get orders error: {e}")
        return []

@api_router.get("/orders/{order_id}")
async def get_order(order_id: str):
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        order = await db.orders.find_one({'id': order_id})
        if not order:
            raise HTTPException(404, "Order not found")
        
        order.pop('_id', None)
        return order
    except HTTPException:
        raise
    except Exception as e:
        print(f"Get order error: {e}")
        raise HTTPException(500, "Failed to get order")

@api_router.put("/orders/{order_id}/status")
async def update_order_status(order_id: str, data: dict, current_user: dict = Depends(verify_token)):
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        update_data = {'status': data['status']}
        
        if data['status'] == 'delivered':
            update_data['delivered_at'] = datetime.now(timezone.utc).isoformat()
        
        await db.orders.update_one({'id': order_id}, {'$set': update_data})
        return {"message": "Order status updated"}
    except Exception as e:
        print(f"Update order status error: {e}")
        raise HTTPException(500, "Failed to update order status")

@api_router.put("/orders/{order_id}/assign")
async def assign_delivery(order_id: str, data: dict, current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        await db.orders.update_one({'id': order_id}, {'$set': {
            'delivery_partner_id': data['delivery_partner_id'],
            'delivery_partner_name': data['delivery_partner_name']
        }})
        return {"message": "Delivery partner assigned"}
    except Exception as e:
        print(f"Assign delivery error: {e}")
        raise HTTPException(500, "Failed to assign delivery")

# DELIVERY PARTNERS
@api_router.get("/delivery-partners")
async def get_delivery_partners(current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        return []
    
    try:
        partners = []
        async for doc in db.users.find({'role': 'delivery'}):
            partners.append({
                'id': doc['id'],
                'full_name': doc['full_name'],
                'mobile': doc.get('mobile', '')
            })
        return partners
    except Exception as e:
        print(f"Get delivery partners error: {e}")
        return []

@api_router.post("/orders/{order_id}/verify-delivery-otp")
async def verify_delivery_otp(order_id: str, data: dict, current_user: dict = Depends(verify_token)):
    """
    Verify delivery OTP and mark order as delivered
    """
    if current_user['role'] != 'delivery':
        raise HTTPException(403, "Delivery partner only")
    
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        # Get order
        order = await db.orders.find_one({'id': order_id})
        if not order:
            raise HTTPException(404, "Order not found")
        
        # Verify OTP
        if order.get('delivery_otp') != data.get('otp'):
            raise HTTPException(400, "Invalid OTP")
        
        # Mark as delivered
        await db.orders.update_one(
            {'id': order_id},
            {'$set': {
                'status': 'delivered',
                'delivered_at': datetime.now(timezone.utc).isoformat()
            }}
        )
        
        return {"message": "Order delivered successfully", "success": True}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Verify delivery OTP error: {e}")
        raise HTTPException(500, "Failed to verify OTP")

# DASHBOARD STATS
@api_router.get("/dashboard/stats")
async def get_dashboard_stats(current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        return {
            "total_orders": 0,
            "pending_orders": 0,
            "delivered_orders": 0,
            "total_sales": 0,
            "low_stock_products": 0
        }
    
    try:
        # Get all orders
        all_orders = []
        async for order in db.orders.find():
            all_orders.append(order)
        
        total_orders = len(all_orders)
        pending = sum(1 for o in all_orders if o['status'] == 'pending')
        delivered = sum(1 for o in all_orders if o['status'] == 'delivered')
        total_sales = sum(o['total_amount'] for o in all_orders if o['status'] == 'delivered')
        
        # Get low stock products
        low_stock = await db.products.count_documents({'stock': {'$lt': 10}})
        
        return {
            "total_orders": total_orders,
            "pending_orders": pending,
            "delivered_orders": delivered,
            "total_sales": total_sales,
            "low_stock_products": low_stock
        }
    except Exception as e:
        print(f"Dashboard stats error: {e}")
        return {
            "total_orders": 0,
            "pending_orders": 0,
            "delivered_orders": 0,
            "total_sales": 0,
            "low_stock_products": 0
        }

# SALES REPORTS
@api_router.get("/sales/daily")
async def get_daily_sales(date: Optional[str] = None, current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        return []
    
    try:
        target_date = date if date else datetime.now(timezone.utc).strftime("%Y-%m-%d")
        
        # Get orders for the specified date
        orders = []
        async for order in db.orders.find({'status': 'delivered'}):
            order_date = datetime.fromisoformat(order['created_at']).strftime("%Y-%m-%d")
            if order_date == target_date:
                order.pop('_id', None)
                orders.append(order)
        
        total_sales = sum(o['total_amount'] for o in orders)
        
        return {
            "date": target_date,
            "orders": orders,
            "total_orders": len(orders),
            "total_sales": total_sales
        }
    except Exception as e:
        print(f"Daily sales error: {e}")
        return []

@api_router.get("/sales/weekly")
async def get_weekly_sales(current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        return []
    
    try:
        # Get last 7 days
        today = datetime.now(timezone.utc)
        week_ago = today - timedelta(days=7)
        
        orders = []
        async for order in db.orders.find({'status': 'delivered'}):
            order_date = datetime.fromisoformat(order['created_at'])
            if order_date >= week_ago:
                order.pop('_id', None)
                orders.append(order)
        
        total_sales = sum(o['total_amount'] for o in orders)
        
        return {
            "period": "Last 7 days",
            "orders": orders,
            "total_orders": len(orders),
            "total_sales": total_sales
        }
    except Exception as e:
        print(f"Weekly sales error: {e}")
        return []

@api_router.get("/sales/monthly")
async def get_monthly_sales(month: Optional[str] = None, current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        return []
    
    try:
        target_month = month if month else datetime.now(timezone.utc).strftime("%Y-%m")
        
        orders = []
        async for order in db.orders.find({'status': 'delivered'}):
            order_month = datetime.fromisoformat(order['created_at']).strftime("%Y-%m")
            if order_month == target_month:
                order.pop('_id', None)
                orders.append(order)
        
        total_sales = sum(o['total_amount'] for o in orders)
        
        return {
            "month": target_month,
            "orders": orders,
            "total_orders": len(orders),
            "total_sales": total_sales
        }
    except Exception as e:
        print(f"Monthly sales error: {e}")
        return []

# USER TRACKING
@api_router.get("/users/all")
async def get_all_users(current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        return []
    
    try:
        users = []
        async for customer in db.customers.find():
            customer.pop('_id', None)
            # Get order count for this customer
            order_count = await db.orders.count_documents({'customer_id': customer['id']})
            customer['order_count'] = order_count
            users.append(customer)
        
        return users
    except Exception as e:
        print(f"Get users error: {e}")
        return []

# SETTINGS
@api_router.get("/settings")
async def get_settings():
    try:
        if db is None:
            return Settings().model_dump()
        
        doc = await db.settings.find_one({'_id': 'app_settings'})
        if doc:
            doc.pop('_id', None)
            return doc
        return Settings().model_dump()
    except Exception as e:
        print(f"Error loading settings: {e}")
        return Settings().model_dump()

@api_router.put("/settings")
async def update_settings(settings: Settings, current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        settings_data = settings.model_dump()
        await db.settings.update_one(
            {'_id': 'app_settings'},
            {'$set': settings_data},
            upsert=True
        )
        return settings
    except Exception as e:
        print(f"Update settings error: {e}")
        raise HTTPException(500, "Failed to update settings")

# IMAGE UPLOAD TO FIREBASE STORAGE
@api_router.post("/upload-image")
async def upload_image(file: UploadFile = File(...), current_user: dict = Depends(verify_token)):
    if current_user['role'] != 'admin':
        raise HTTPException(403, "Admin only")
    
    try:
        # Read file content
        contents = await file.read()
        
        # Generate unique filename
        file_extension = file.filename.split('.')[-1]
        unique_filename = f"products/{uuid.uuid4()}.{file_extension}"
        
        # Upload to Firebase Storage
        bucket = storage.bucket()
        blob = bucket.blob(unique_filename)
        blob.upload_from_string(contents, content_type=file.content_type)
        
        # Make the file publicly accessible
        blob.make_public()
        
        # Get public URL
        public_url = blob.public_url
        
        return {"url": public_url, "filename": unique_filename}
    except Exception as e:
        print(f"Image upload error: {e}")
        raise HTTPException(500, f"Failed to upload image: {str(e)}")

# SEARCH PRODUCTS (for live search)
@api_router.get("/search")
async def search_products(q: str = ""):
    try:
        if not q or len(q) < 1:
            return []
        
        if db is None:
            return []
        
        # Search in product name (case-insensitive)
        query = {
            'is_active': True,
            '$or': [
                {'name': {'$regex': q, '$options': 'i'}},
                {'name_gu': {'$regex': q, '$options': 'i'}}
            ]
        }
        
        products_list = []
        async for doc in db.products.find(query).limit(20):
            doc.pop('_id', None)
            products_list.append(doc)
        
        return products_list
    except Exception as e:
        print(f"Search error: {e}")
        return []

# GENERATE INVOICE (Gujarati support)
@api_router.get("/invoice/{order_id}")
async def generate_invoice(order_id: str, lang: str = "en"):
    try:
        if db is None:
            raise HTTPException(500, "Database not initialized")
        
        # Get order details
        order = await db.orders.find_one({'id': order_id})
        if not order:
            raise HTTPException(404, "Order not found")
        
        # Get settings for company info
        settings_doc = await db.settings.find_one({'_id': 'app_settings'})
        settings_data = settings_doc if settings_doc else {}
        
        # Create PDF in memory
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        
        # Title
        pdf.setFont("Helvetica-Bold", 20)
        title = "ઇન્વૉઇસ" if lang == "gu" else "INVOICE"
        pdf.drawCentredString(width / 2, height - 50, title)
        
        # Company Name
        pdf.setFont("Helvetica-Bold", 16)
        company_name = "પવનપુત્ર મેગા માર્ટ" if lang == "gu" else "Pavanputra Mega Mart"
        pdf.drawCentredString(width / 2, height - 80, company_name)
        
        # Tagline
        pdf.setFont("Helvetica", 10)
        tagline = settings_data.get('tagline_gu' if lang == 'gu' else 'tagline', 'Tamara Vyapar no Sacho Sathi')
        pdf.drawCentredString(width / 2, height - 100, tagline)
        
        # Order Details
        y_position = height - 140
        pdf.setFont("Helvetica-Bold", 12)
        order_label = "ઓર્ડર નંબર:" if lang == "gu" else "Order ID:"
        pdf.drawString(50, y_position, f"{order_label} {order['id'][:8]}")
        
        y_position -= 20
        date_label = "તારીખ:" if lang == "gu" else "Date:"
        order_date = datetime.fromisoformat(order['created_at']).strftime("%d/%m/%Y")
        pdf.drawString(50, y_position, f"{date_label} {order_date}")
        
        # Customer Details
        y_position -= 40
        pdf.setFont("Helvetica-Bold", 12)
        customer_label = "ગ્રાહક વિગતો:" if lang == "gu" else "Customer Details:"
        pdf.drawString(50, y_position, customer_label)
        
        pdf.setFont("Helvetica", 10)
        customer_info = order.get('customer_info', {})
        y_position -= 20
        pdf.drawString(50, y_position, f"{customer_info.get('shop_name', 'N/A')}")
        y_position -= 15
        pdf.drawString(50, y_position, f"{customer_info.get('owner_name', 'N/A')} | {customer_info.get('mobile', 'N/A')}")
        y_position -= 15
        pdf.drawString(50, y_position, f"{customer_info.get('address', 'N/A')}, {customer_info.get('pincode', 'N/A')}")
        
        # Items Table
        y_position -= 40
        pdf.setFont("Helvetica-Bold", 12)
        items_label = "વસ્તુઓ:" if lang == "gu" else "Items:"
        pdf.drawString(50, y_position, items_label)
        
        # Table headers
        y_position -= 25
        pdf.setFont("Helvetica-Bold", 9)
        headers = ["વસ્તુ", "જથ્થો", "એકમ", "કિંમત", "છૂટ", "કુલ"] if lang == "gu" else ["Item", "Qty", "Unit", "Price", "Discount", "Total"]
        pdf.drawString(50, y_position, headers[0])
        pdf.drawString(200, y_position, headers[1])
        pdf.drawString(250, y_position, headers[2])
        pdf.drawString(300, y_position, headers[3])
        pdf.drawString(380, y_position, headers[4])
        pdf.drawString(450, y_position, headers[5])
        
        # Draw line
        y_position -= 5
        pdf.line(50, y_position, width - 50, y_position)
        
        # Items
        pdf.setFont("Helvetica", 9)
        for item in order.get('items', []):
            y_position -= 20
            item_total = item['quantity'] * item['price'] * (1 - item.get('discount', 0) / 100)
            
            pdf.drawString(50, y_position, item.get('product_name', '')[:20])
            pdf.drawString(200, y_position, str(item['quantity']))
            pdf.drawString(250, y_position, item.get('unit', ''))
            pdf.drawString(300, y_position, f"₹{item['price']:.2f}")
            pdf.drawString(380, y_position, f"{item.get('discount', 0)}%")
            pdf.drawString(450, y_position, f"₹{item_total:.2f}")
        
        # Total
        y_position -= 30
        pdf.line(50, y_position, width - 50, y_position)
        y_position -= 20
        pdf.setFont("Helvetica-Bold", 12)
        total_label = "કુલ રકમ:" if lang == "gu" else "Total Amount:"
        pdf.drawString(350, y_position, total_label)
        pdf.drawString(450, y_position, f"₹{order['total_amount']:.2f}")
        
        # Footer
        y_position = 100
        pdf.setFont("Helvetica", 8)
        footer_text = "આભાર! ફરીથી આવજો!" if lang == "gu" else "Thank you for your business!"
        pdf.drawCentredString(width / 2, y_position, footer_text)
        
        pdf.save()
        buffer.seek(0)
        
        return Response(
            content=buffer.getvalue(),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=invoice_{order_id[:8]}.pdf"}
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Invoice generation error: {e}")
        raise HTTPException(500, f"Failed to generate invoice: {str(e)}")

# INITIALIZE DEMO DATA
@api_router.post("/init-demo-data")
async def init_demo_data():
    if db is None:
        raise HTTPException(500, "Database not initialized")
    
    try:
        # Create default admin
        admin_id = str(uuid.uuid4())
        admin_exists = await db.users.find_one({'username': 'admin'})
        if not admin_exists:
            await db.users.insert_one({
                "id": admin_id,
                "username": "admin",
                "password": hash_password("admin123"),
                "role": "admin",
                "full_name": "Admin User",
                "created_at": datetime.now(timezone.utc).isoformat()
            })
        
        # Demo categories
        demo_categories = await get_demo_categories()
        for cat in demo_categories:
            existing = await db.categories.find_one({'id': cat['id']})
            if not existing:
                await db.categories.insert_one(cat)
        
        # Demo products
        demo_products = await get_demo_products()
        for prod in demo_products:
            existing = await db.products.find_one({'id': prod['id']})
            if not existing:
                await db.products.insert_one(prod)
        
        # Settings
        settings = Settings(logo_url="https://customer-assets.emergentagent.com/job_b2b-bazaar/artifacts/d6c8x24d_Lucid_Origin_A_professional_3D_logo_design_for_Pavanputra_Mega_1.jpg")
        await db.settings.update_one(
            {'_id': 'app_settings'},
            {'$set': settings.model_dump()},
            upsert=True
        )
        
        return {"message": "Demo data initialized successfully"}
    except Exception as e:
        print(f"Init demo data error: {e}")
        raise HTTPException(500, "Failed to initialize demo data")

# DEMO DATA HELPERS
async def get_demo_categories():
    return [
        {"id": "cat1", "name": "Grocery", "name_gu": "કરિયાણું", "order": 1, "is_visible": True, "visible_to_users": [], "image_urls": [
            "https://images.unsplash.com/photo-1586201375761-83865001e31c?w=400",
            "https://images.unsplash.com/photo-1516594798947-e65505dbb29d?w=400",
            "https://images.unsplash.com/photo-1574856344991-aaa31b6f4ce3?w=400",
            "https://images.unsplash.com/photo-1571755345857-d4d089edf9c7?w=400"
        ], "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "cat2", "name": "Pan & Cold Drink", "name_gu": "પાન અને કોલ્ડ ડ્રિંક", "order": 2, "is_visible": True, "visible_to_users": [], "image_urls": [
            "https://images.unsplash.com/photo-1629203849068-752d7b4023bc?w=400",
            "https://images.unsplash.com/photo-1622483767028-3f66f32aef97?w=400",
            "https://images.unsplash.com/photo-1581006852262-e4307cf6283a?w=400",
            "https://images.unsplash.com/photo-1570831739435-6601aa3fa4fb?w=400"
        ], "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "cat3", "name": "Mobile Accessories", "name_gu": "મોબાઈલ એસેસરીઝ", "order": 3, "is_visible": True, "visible_to_users": [], "image_urls": [
            "https://images.unsplash.com/photo-1556656793-08538906a9f8?w=400",
            "https://images.unsplash.com/photo-1484704849700-f032a568e944?w=400",
            "https://images.unsplash.com/photo-1590658268037-6bf12165a8df?w=400",
            "https://images.unsplash.com/photo-1609081219090-a6d81d3085bf?w=400"
        ], "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "cat4", "name": "Electronics", "name_gu": "ઈલેક્ટ્રોનિક્સ", "order": 4, "is_visible": True, "visible_to_users": [], "image_urls": [
            "https://images.unsplash.com/photo-1550009158-9ebf69173e03?w=400",
            "https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=400",
            "https://images.unsplash.com/photo-1573883430060-e0815f63031d?w=400",
            "https://images.unsplash.com/photo-1517059224940-d4af9eec41b7?w=400"
        ], "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "cat5", "name": "Personal Care", "name_gu": "વ્યક્તિગત સંભાળ", "order": 5, "is_visible": True, "visible_to_users": [], "image_urls": [
            "https://images.unsplash.com/photo-1556228852-80c4d2144e2c?w=400",
            "https://images.unsplash.com/photo-1571875257727-256c39da42af?w=400",
            "https://images.unsplash.com/photo-1608248543803-ba4f8c70ae0b?w=400",
            "https://images.unsplash.com/photo-1629198726116-b122f99bdfbd?w=400"
        ], "created_at": datetime.now(timezone.utc).isoformat()}
    ]

async def get_demo_products(category_id: Optional[str] = None):
    all_products = [
        {"id": "p1", "name": "Wheat Flour", "name_gu": "ઘઉં નો લોટ", "category_id": "cat1", "price": 450, "unit": "Kg", "discount": 5, "image_url": "https://images.unsplash.com/photo-1586201375761-83865001e31c?w=400", "images": ["https://images.unsplash.com/photo-1586201375761-83865001e31c?w=400"], "description": "Premium quality wheat flour for daily use", "description_gu": "દૈનિક વપરાશ માટે પ્રીમિયમ ક્વાલિટી ઘઉંનો લોટ", "stock": 100, "rating": 4.5, "delivery_time": "Next Day", "is_active": True, "bulk_package_size": 30, "bulk_package_unit": "Kg", "small_package_size": 1, "small_package_unit": "Kg", "small_packages_per_bulk": 30, "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "p2", "name": "Basmati Rice", "name_gu": "બાસમતી ચોખા", "category_id": "cat1", "price": 850, "unit": "Kg", "discount": 10, "image_url": "https://images.unsplash.com/photo-1516594798947-e65505dbb29d?w=400", "images": ["https://images.unsplash.com/photo-1516594798947-e65505dbb29d?w=400"], "description": "Premium basmati rice with long grains", "description_gu": "લાંબા દાણાવાળા પ્રીમિયમ બાસમતી ચોખા", "stock": 80, "rating": 4.7, "delivery_time": "Next Day", "is_active": True, "bulk_package_size": 25, "bulk_package_unit": "Kg", "small_package_size": 1, "small_package_unit": "Kg", "small_packages_per_bulk": 25, "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "p3", "name": "Sugar", "name_gu": "ખાંડ", "category_id": "cat1", "price": 420, "unit": "Kg", "discount": 0, "image_url": "https://images.unsplash.com/photo-1574856344991-aaa31b6f4ce3?w=400", "images": ["https://images.unsplash.com/photo-1574856344991-aaa31b6f4ce3?w=400"], "description": "Pure white sugar for sweetness", "description_gu": "મીઠાશ માટે શુદ્ધ સફેદ ખાંડ", "stock": 120, "rating": 4.3, "delivery_time": "Next Day", "is_active": True, "bulk_package_size": 50, "bulk_package_unit": "Kg", "small_package_size": 1, "small_package_unit": "Kg", "small_packages_per_bulk": 50, "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "p4", "name": "Pepsi", "name_gu": "પેપ્સી", "category_id": "cat2", "price": 380, "unit": "Box", "discount": 15, "image_url": "https://images.unsplash.com/photo-1629203849068-752d7b4023bc?w=400", "images": ["https://images.unsplash.com/photo-1629203849068-752d7b4023bc?w=400"], "description": "Refreshing cola drink - 12 bottles per box", "description_gu": "તાજગીભર્યું કોલા ડ્રિંક - બોક્સમાં 12 બોટલ", "stock": 50, "rating": 4.6, "delivery_time": "Next Day", "is_active": True, "bulk_package_size": 12, "bulk_package_unit": "Box", "small_package_size": 1, "small_package_unit": "Bottle", "small_packages_per_bulk": 12, "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "p5", "name": "Thums Up", "name_gu": "થમ્સ અપ", "category_id": "cat2", "price": 390, "unit": "Box", "discount": 10, "image_url": "https://images.unsplash.com/photo-1622483767028-3f66f32aef97?w=400", "images": ["https://images.unsplash.com/photo-1622483767028-3f66f32aef97?w=400"], "description": "Strong fizzy cola - 12 bottles per box", "description_gu": "મજબૂત ફિઝી કોલા - બોક્સમાં 12 બોટલ", "stock": 60, "rating": 4.8, "delivery_time": "Next Day", "is_active": True, "bulk_package_size": 12, "bulk_package_unit": "Box", "small_package_size": 1, "small_package_unit": "Bottle", "small_packages_per_bulk": 12, "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "p6", "name": "Pan Masala", "name_gu": "પાન મસાલા", "category_id": "cat2", "price": 150, "unit": "Box", "discount": 0, "image_url": "https://images.unsplash.com/photo-1581006852262-e4307cf6283a?w=400", "images": ["https://images.unsplash.com/photo-1581006852262-e4307cf6283a?w=400"], "description": "Fresh pan masala - 50 sachets per box", "description_gu": "તાજું પાન મસાલા - બોક્સમાં 50 પેકેટ", "stock": 200, "rating": 4.2, "delivery_time": "Next Day", "is_active": True, "bulk_package_size": 50, "bulk_package_unit": "Box", "small_package_size": 1, "small_package_unit": "Sachet", "small_packages_per_bulk": 50, "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "p7", "name": "Mobile Charger", "name_gu": "મોબાઇલ ચાર્જર", "category_id": "cat3", "price": 250, "unit": "Piece", "discount": 20, "image_url": "https://images.unsplash.com/photo-1556656793-08538906a9f8?w=400", "images": ["https://images.unsplash.com/photo-1556656793-08538906a9f8?w=400"], "description": "Fast charging mobile charger", "description_gu": "ઝડપી ચાર્જિંગ મોબાઇલ ચાર્જર", "stock": 100, "rating": 4.4, "delivery_time": "Next Day", "is_active": True, "bulk_package_size": 0, "bulk_package_unit": "", "small_package_size": 0, "small_package_unit": "", "small_packages_per_bulk": 0, "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "p8", "name": "Earphones", "name_gu": "ઇયરફોન્સ", "category_id": "cat3", "price": 180, "unit": "Piece", "discount": 15, "image_url": "https://images.unsplash.com/photo-1484704849700-f032a568e944?w=400", "images": ["https://images.unsplash.com/photo-1484704849700-f032a568e944?w=400"], "description": "High quality sound earphones", "description_gu": "ઉચ્ચ ગુણવત્તાવાળા ધ્વનિ ઇયરફોન્સ", "stock": 150, "rating": 4.1, "delivery_time": "Next Day", "is_active": True, "bulk_package_size": 0, "bulk_package_unit": "", "small_package_size": 0, "small_package_unit": "", "small_packages_per_bulk": 0, "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "p9", "name": "LED Bulb", "name_gu": "LED બલ્બ", "category_id": "cat4", "price": 120, "unit": "Piece", "discount": 10, "image_url": "https://images.unsplash.com/photo-1550009158-9ebf69173e03?w=400", "images": ["https://images.unsplash.com/photo-1550009158-9ebf69173e03?w=400"], "description": "Energy saving LED bulb 9W", "description_gu": "ઊર્જા બચાવતો LED બલ્બ 9W", "stock": 200, "rating": 4.5, "delivery_time": "Next Day", "is_active": True, "bulk_package_size": 0, "bulk_package_unit": "", "small_package_size": 0, "small_package_unit": "", "small_packages_per_bulk": 0, "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "p10", "name": "Extension Board", "name_gu": "એક્સ્ટેન્શન બોર્ડ", "category_id": "cat4", "price": 350, "unit": "Piece", "discount": 5, "image_url": "https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=400", "images": ["https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=400"], "description": "6 socket extension board with switch", "description_gu": "સ્વિચ સાથે 6 સોકેટ એક્સ્ટેન્શન બોર્ડ", "stock": 80, "rating": 4.6, "delivery_time": "Next Day", "is_active": True, "bulk_package_size": 0, "bulk_package_unit": "", "small_package_size": 0, "small_package_unit": "", "small_packages_per_bulk": 0, "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "p11", "name": "Soap", "name_gu": "સાબુ", "category_id": "cat5", "price": 280, "unit": "Box", "discount": 12, "image_url": "https://images.unsplash.com/photo-1556228852-80c4d2144e2c?w=400", "images": ["https://images.unsplash.com/photo-1556228852-80c4d2144e2c?w=400"], "description": "Premium bathing soap - 12 pieces per box", "description_gu": "પ્રીમિયમ નહાવાનો સાબુ - બોક્સમાં 12 પીસ", "stock": 150, "rating": 4.4, "delivery_time": "Next Day", "is_active": True, "bulk_package_size": 12, "bulk_package_unit": "Box", "small_package_size": 1, "small_package_unit": "Piece", "small_packages_per_bulk": 12, "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": "p12", "name": "Shampoo", "name_gu": "શેમ્પૂ", "category_id": "cat5", "price": 320, "unit": "Box", "discount": 15, "image_url": "https://images.unsplash.com/photo-1571875257727-256c39da42af?w=400", "images": ["https://images.unsplash.com/photo-1571875257727-256c39da42af?w=400"], "description": "Hair care shampoo - 6 bottles per box", "description_gu": "વાળની સંભાળ શેમ્પૂ - બોક્સમાં 6 બોટલ", "stock": 100, "rating": 4.7, "delivery_time": "Next Day", "is_active": True, "bulk_package_size": 6, "bulk_package_unit": "Box", "small_package_size": 1, "small_package_unit": "Bottle", "small_packages_per_bulk": 6, "created_at": datetime.now(timezone.utc).isoformat()}
    ]
    
    if category_id:
        return [p for p in all_products if p['category_id'] == category_id]
    return all_products

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
