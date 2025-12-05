require('dotenv').config();
const express = require('express');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Create Cloudinary storage engine for Multer
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'damodar-traders',
    allowed_formats: ['jpg', 'jpeg', 'png', 'gif'],
    transformation: [{ width: 800, height: 800, crop: 'limit' }]
  }
});

const upload = multer({ 
  storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    
    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed (JPEG, JPG, PNG, GIF)'));
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// MongoDB Atlas connection - UPDATED CONNECTION STRING
const uri = process.env.MONGODB_URI || "mongodb+srv://rajat:rajat888@cluster0.psa8nvb.mongodb.net/damodarTraders?retryWrites=true&w=majority&appName=Cluster0";

// UPDATED MongoClient configuration with proper TLS settings
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  // SSL/TLS Configuration
  tls: true,
  tlsAllowInvalidCertificates: false, // Keep false for production
  // Connection pooling
  maxPoolSize: 50,
  minPoolSize: 5,
  maxIdleTimeMS: 30000,
  // Timeouts
  connectTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  // Retry logic
  retryWrites: true,
  retryReads: true,
  w: 'majority',
  readPreference: 'primary'
});

// Enhanced CORS configuration
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:5500','http://127.0.0.1:3001','https://686fdbf5c817f20ef495d5ac--charming-gumption-ebc6bd.netlify.app','http://localhost:8000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Middleware
app.use(express.json());                               
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'admin123',
  resave: true,
  saveUninitialized: false,
  cookie: { 
    secure: false,
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Static files
app.use(express.static(path.join(__dirname, '../public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Database connection with better error handling
async function connectToDB() {
  try {
    console.log("🔌 Attempting to connect to MongoDB Atlas...");
    
    // Log connection details (without password)
    const maskedUri = uri.replace(/\/\/([^:]+):([^@]+)@/, '//$1:****@');
    console.log("Connection string:", maskedUri);
    
    await client.connect();
    
    // Send a ping to confirm successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("✅ Successfully connected to MongoDB Atlas!");
    
    return client.db('damodarTraders');
  } catch (err) {
    console.error("❌ MongoDB connection error:", err.message);
    
    // More detailed error information
    if (err.code === 'ETIMEDOUT') {
      console.error("Network timeout - check your internet connection");
    } else if (err.code === 'ENOTFOUND') {
      console.error("DNS lookup failed - check your connection string");
    } else if (err.message.includes('SSL')) {
      console.error("SSL/TLS issue detected. Trying alternative connection method...");
      
      // Try alternative connection without TLS for debugging
      console.log("For development, you might try:");
      console.log("1. Update Node.js to latest LTS version");
      console.log("2. Install latest MongoDB driver: npm install mongodb@latest");
      console.log("3. Check if you're behind a corporate firewall/proxy");
    }
    
    throw err;
  }
}

// Create admin user if not exists
async function createAdminUser() {
  try {
    const db = await connectToDB();
    const adminCollection = db.collection('adminUsers');
    
    const adminExists = await adminCollection.findOne({ username: 'admin' });
    
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await adminCollection.insertOne({
        username: 'admin',
        password: hashedPassword,
        createdAt: new Date()
      });
      console.log('✅ Default admin user created');
    } else {
      console.log('✅ Admin user already exists');
    }
  } catch (err) {
    console.error('❌ Failed to create admin user:', err.message);
  }
}

// Create default categories if not exists
async function createDefaultCategories() {
  try {
    const db = await connectToDB();
    const categoriesCollection = db.collection('categories');
    
    const defaultCategories = [
      { name: 'Pipes', slug: 'pipes', description: 'Various types of pipes', createdAt: new Date() },
      { name: 'Fittings', slug: 'fittings', description: 'Pipe fittings and connectors', createdAt: new Date() },
      { name: 'Valves', slug: 'valves', description: 'Different valve types', createdAt: new Date() }
    ];
    
    const existingCategories = await categoriesCollection.countDocuments();
    
    if (existingCategories === 0) {
      await categoriesCollection.insertMany(defaultCategories);
      console.log('✅ Default categories created');
    } else {
      console.log('✅ Categories already exist');
    }
  } catch (err) {
    console.error('❌ Failed to create default categories:', err.message);
  }
}

// Enhanced auth middleware
function requireAuth(req, res, next) {
  if (!req.session.admin) {
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    return res.redirect('/admin/login');
  }
  next();
}

// Login routes
app.get('/admin/login', (req, res) => {
  if (req.session.admin) {
    return res.redirect('/admin');
  }
  res.sendFile(path.join(__dirname, '../public/login.html'));
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const db = await connectToDB();
    const adminCollection = db.collection('adminUsers');
    const admin = await adminCollection.findOne({ username });

    if (!admin) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, admin.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    req.session.admin = {
      id: admin._id,
      username: admin.username
    };

    req.session.save(err => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({ error: 'Login failed' });
      }
      res.json({ message: 'Login successful', redirect: '/admin' });
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout route
app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Logout successful', redirect: '/admin/login' });
  });
});

// Check auth status
app.get('/api/admin/status', (req, res) => {
  if (req.session.admin) {
    res.json({ authenticated: true, username: req.session.admin.username });
  } else {
    res.json({ authenticated: false });
  }
});

// Admin panel route
app.get('/admin', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin.html'));
});

// Serve static files without auth middleware
app.use('/admin', express.static(path.join(__dirname, '../public')));

// Public product routes
app.get('/api/products', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const products = await productsCollection.find().sort({ createdAt: -1 }).toArray();
    res.json(products);
  } catch (err) {
    console.error('Error fetching products:', err);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

app.get('/api/products/category/:category', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const products = await productsCollection.find({ 
      category: req.params.category 
    }).sort({ createdAt: -1 }).toArray();
    res.json(products);
  } catch (err) {
    console.error('Error fetching products by category:', err);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const product = await productsCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json(product);
  } catch (err) {
    console.error('Error fetching product:', err);
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

// Public category routes
app.get('/api/categories', async (req, res) => {
  try {
    const db = await connectToDB();
    const categoriesCollection = db.collection('categories');
    const categories = await categoriesCollection.find().sort({ name: 1 }).toArray();
    res.json(categories);
  } catch (err) {
    console.error('Error fetching categories:', err);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

app.get('/api/categories/:slug', async (req, res) => {
  try {
    const db = await connectToDB();
    const categoriesCollection = db.collection('categories');
    const category = await categoriesCollection.findOne({ 
      slug: req.params.slug 
    });
    
    if (!category) {
      return res.status(404).json({ error: 'Category not found' });
    }
    res.json(category);
  } catch (err) {
    console.error('Error fetching category:', err);
    res.status(500).json({ error: 'Failed to fetch category' });
  }
});

// Protected admin API routes
app.use('/api/admin', requireAuth);

// Product management routes (protected)
app.get('/api/admin/products', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const products = await productsCollection.find().sort({ createdAt: -1 }).toArray();
    res.json(products);
  } catch (err) {
    console.error('Error fetching products:', err);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

app.get('/api/admin/products/:id', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const product = await productsCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json(product);
  } catch (err) {
    console.error('Error fetching product:', err);
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

app.post('/api/admin/products', upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Please upload an image' });
  }

  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');

    const newProduct = {
      name: req.body.name || 'New Product',
      image: req.file.path, // Cloudinary URL
      imagePublicId: req.file.filename, // Cloudinary public_id
      category: req.body.category || 'pipes',
      description: req.body.description || '',
      sizeOptions: req.body.sizeOptions ? JSON.parse(req.body.sizeOptions) : [{ size: '', price: 0 }],
      discount: parseFloat(req.body.discount) || 0,
      material: req.body.material || '',
      pressureRating: req.body.pressureRating || '',
      temperatureRange: req.body.temperatureRange || '',
      standards: req.body.standards || '',
      application: req.body.application || '',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const result = await productsCollection.insertOne(newProduct);
    res.status(201).json({ ...newProduct, _id: result.insertedId });
  } catch (err) {
    console.error('Error creating product:', err);
    
    // Delete the uploaded image from Cloudinary if product creation fails
    if (req.file) {
      try {
        await cloudinary.uploader.destroy(req.file.filename);
      } catch (cloudinaryErr) {
        console.error('Error cleaning up Cloudinary image:', cloudinaryErr);
      }
    }
    
    res.status(500).json({ error: 'Failed to create product' });
  }
});

app.put('/api/admin/products/:id', upload.single('image'), async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');

    const existingProduct = await productsCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    
    if (!existingProduct) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const updateData = {
      name: req.body.name || existingProduct.name,
      category: req.body.category || existingProduct.category,
      description: req.body.description || existingProduct.description,
      sizeOptions: req.body.sizeOptions ? JSON.parse(req.body.sizeOptions) : existingProduct.sizeOptions,
      discount: parseFloat(req.body.discount) || existingProduct.discount,
      material: req.body.material || existingProduct.material,
      pressureRating: req.body.pressureRating || existingProduct.pressureRating,
      temperatureRange: req.body.temperatureRange || existingProduct.temperatureRange,
      standards: req.body.standards || existingProduct.standards,
      application: req.body.application || existingProduct.application,
      updatedAt: new Date()
    };

    if (req.file) {
      // Delete old image from Cloudinary if it exists
      if (existingProduct.imagePublicId) {
        try {
          await cloudinary.uploader.destroy(existingProduct.imagePublicId);
        } catch (err) {
          console.error('Error deleting old image from Cloudinary:', err);
        }
      }
      
      updateData.image = req.file.path;
      updateData.imagePublicId = req.file.filename;
    }

    const result = await productsCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: updateData }
    );

    if (result.modifiedCount === 0) {
      return res.status(400).json({ error: 'No changes made to product' });
    }

    const updatedProduct = await productsCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    res.json(updatedProduct);
  } catch (err) {
    console.error('Error updating product:', err);
    
    // Delete the new uploaded image from Cloudinary if update fails
    if (req.file) {
      try {
        await cloudinary.uploader.destroy(req.file.filename);
      } catch (cloudinaryErr) {
        console.error('Error cleaning up Cloudinary image:', cloudinaryErr);
      }
    }
    
    res.status(500).json({ error: 'Failed to update product' });
  }
});

app.delete('/api/admin/products/:id', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');

    const product = await productsCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // Delete image from Cloudinary if it exists
    if (product.imagePublicId) {
      try {
        await cloudinary.uploader.destroy(product.imagePublicId);
      } catch (err) {
        console.error('Error deleting image from Cloudinary:', err);
      }
    }

    const result = await productsCollection.deleteOne({ 
      _id: new ObjectId(req.params.id) 
    });

    res.json({ 
      message: 'Product deleted successfully', 
      deletedCount: result.deletedCount 
    });
  } catch (err) {
    console.error('Error deleting product:', err);
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

// Category management routes (protected)
app.get('/api/admin/categories', async (req, res) => {
  try {
    const db = await connectToDB();
    const categoriesCollection = db.collection('categories');
    const categories = await categoriesCollection.find().sort({ name: 1 }).toArray();
    res.json(categories);
  } catch (err) {
    console.error('Error fetching categories:', err);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

app.get('/api/admin/categories/:id', async (req, res) => {
  try {
    const db = await connectToDB();
    const categoriesCollection = db.collection('categories');
    const category = await categoriesCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    
    if (!category) {
      return res.status(404).json({ error: 'Category not found' });
    }
    res.json(category);
  } catch (err) {
    console.error('Error fetching category:', err);
    res.status(500).json({ error: 'Failed to fetch category' });
  }
});

app.post('/api/admin/categories', async (req, res) => {
  try {
    const { name, slug, description } = req.body;
    
    if (!name || !slug) {
      return res.status(400).json({ error: 'Name and slug are required' });
    }

    const db = await connectToDB();
    const categoriesCollection = db.collection('categories');

    // Check if slug already exists
    const existingCategory = await categoriesCollection.findOne({ slug });
    if (existingCategory) {
      return res.status(400).json({ error: 'Category with this slug already exists' });
    }

    const newCategory = {
      name,
      slug,
      description: description || '',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const result = await categoriesCollection.insertOne(newCategory);
    res.status(201).json({ ...newCategory, _id: result.insertedId });
  } catch (err) {
    console.error('Error creating category:', err);
    res.status(500).json({ error: 'Failed to create category' });
  }
});

app.put('/api/admin/categories/:id', async (req, res) => {
  try {
    const db = await connectToDB();
    const categoriesCollection = db.collection('categories');

    const existingCategory = await categoriesCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    
    if (!existingCategory) {
      return res.status(404).json({ error: 'Category not found' });
    }

    const updateData = {
      name: req.body.name || existingCategory.name,
      slug: req.body.slug || existingCategory.slug,
      description: req.body.description || existingCategory.description,
      updatedAt: new Date()
    };

    // Check if new slug conflicts with other categories
    if (req.body.slug && req.body.slug !== existingCategory.slug) {
      const slugExists = await categoriesCollection.findOne({ 
        slug: req.body.slug,
        _id: { $ne: new ObjectId(req.params.id) }
      });
      if (slugExists) {
        return res.status(400).json({ error: 'Category with this slug already exists' });
      }
    }

    const result = await categoriesCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: updateData }
    );

    if (result.modifiedCount === 0) {
      return res.status(400).json({ error: 'No changes made to category' });
    }

    const updatedCategory = await categoriesCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    res.json(updatedCategory);
  } catch (err) {
    console.error('Error updating category:', err);
    res.status(500).json({ error: 'Failed to update category' });
  }
});

app.delete('/api/admin/categories/:id', async (req, res) => {
  try {
    const db = await connectToDB();
    const categoriesCollection = db.collection('categories');
    const productsCollection = db.collection('products');

    // Check if category is used by any products
    const productsCount = await productsCollection.countDocuments({ 
      category: req.params.id 
    });

    if (productsCount > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete category that has associated products' 
      });
    }

    const result = await categoriesCollection.deleteOne({ 
      _id: new ObjectId(req.params.id) 
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Category not found' });
    }

    res.json({ 
      message: 'Category deleted successfully', 
      deletedCount: result.deletedCount 
    });
  } catch (err) {
    console.error('Error deleting category:', err);
    res.status(500).json({ error: 'Failed to delete category' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'Damodar Traders API'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: err.message || 'Something went wrong!',
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

// Start server
app.listen(PORT, async () => {
  console.log(`🚀 Server starting on port ${PORT}...`);
  console.log(`📁 Public files served from: ${path.join(__dirname, '../public')}`);
  console.log(`🔐 Admin panel: http://localhost:${PORT}/admin`);
  console.log(`🔧 API endpoint: http://localhost:${PORT}/api`);
  
  try {
    await createAdminUser();
    await createDefaultCategories();
    console.log(`✅ Server is running on http://localhost:${PORT}`);
  } catch (err) {
    console.error('❌ Failed to initialize server:', err.message);
    console.log('⚠️ Server is running but database initialization failed');
  }
});

// Close MongoDB connection when process ends
process.on('SIGINT', async () => {
  console.log('\n🛑 Server shutting down...');
  try {
    await client.close();
    console.log('✅ MongoDB connection closed');
  } catch (err) {
    console.error('❌ Error closing MongoDB connection:', err);
  }
  process.exit();
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('⚠️ Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('⚠️ Unhandled Rejection at:', promise, 'reason:', reason);
});