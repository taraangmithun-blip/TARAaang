require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const puppeteer = require('puppeteer');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "greenhaven_secret_key_123"; 
const ADMIN_SECRET_CODE = process.env.ADMIN_SECRET || "admin123"; 
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});

// --- 1. CONFIGURATION & MIDDLEWARE ---
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json());

// --- 2. DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch((err) => { console.error('DB Connection Error:', err); process.exit(1); });

// --- 3. CLOUDINARY CONFIG ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: { folder: 'ecommerce_products', allowed_formats: ['jpg', 'png', 'jpeg', 'webp'] },
});
const upload = multer({ storage: storage });

// --- 4. SECURITY MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    if (!token) return res.status(401).json({ error: "Access Denied" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });
        req.user = user;
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') next();
    else res.status(403).json({ error: "Admins Only" });
};

// ======================================================
// --- 5. SCHEMAS ---
// ======================================================

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'admin' }, 
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const ProductSchema = new mongoose.Schema({
    name: { type: String, required: true },
    category: { type: String, default: "General" },
    description: { type: String, default: "" },
    imageUrl: { type: String, default: "" },
    galleryImages: [{ type: String }],
    pricingMode: { type: String, enum: ['per_item', 'per_area', 'per_length', 'per_weight'], default: 'per_item' },
    unitLabel: { type: String, default: "pc" },
    basePrice: { type: Number, default: 0 },
    variants: [{
        variety: { type: String, default: "Standard" },
        color: { type: String, default: "" },
        height: { type: String, default: "" },
        price: { type: Number, default: 0 },
        countInStock: { type: Number, default: 0 },
        packageWeight: { type: Number, default: 0 }
    }]
}, { timestamps: true });

const Product = mongoose.model('Product', ProductSchema);

const OrderSchema = new mongoose.Schema({
    shortToken: { type: String, required: true },
    customerName: { type: String, required: true },
    customerPhone: { type: String, required: true },
    items: [{
        product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
        name: String, qty: Number, price: Number
    }],
    // --- UPDATED: TAX FIELDS ---
    subtotal: { type: Number, default: 0 },
    taxAmount: { type: Number, default: 0 },
    deliveryFee: { type: Number, default: 0 },
    // ---------------------------
    totalAmount: { type: Number, required: true },
    paymentStatus: { type: String, enum: ['PAID', 'DUE'], default: 'DUE' },
    transactionId: { type: String, default: '' },
    isCollected: { type: Boolean, default: false },
    orderType: { type: String, enum: ['pickup', 'delivery'], default: 'pickup' },
    address: { type: String, default: "" },
}, { timestamps: true });

const Order = mongoose.model('Order', OrderSchema);


// ======================================================
// --- 6. ROUTES ---
// ======================================================

// --- AUTH ROUTES ---
app.post('/api/signup', async (req, res) => {
    try {
        const { name, email, password, adminCode } = req.body;
        if (adminCode !== ADMIN_SECRET_CODE) return res.status(403).json({ error: "Forbidden: Incorrect Admin Code" });
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: "Email exists" });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword, role: 'admin' });
        await newUser.save();
        res.status(201).json({ message: "Admin account created successfully!" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || user.role !== 'admin') return res.status(403).json({ error: "Access Denied" });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user._id, name: user.name, role: user.role } });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- PRODUCT ROUTES ---
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find().sort({ _id: -1 });
        res.json(products);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- STOCK VALIDATION ROUTE (Strict Match) ---
app.post('/api/products/validate-stock', async (req, res) => {
    try {
        const { items } = req.body; 
        const outOfStockItems = [];

        for (const item of items) {
            const product = await Product.findById(item._id || item.id);
            if (!product) { outOfStockItems.push(`Unknown Item`); continue; }

            let availableStock = 0;
            let itemName = product.name;

            // Strict Variant Matching
            if (item.variant && product.variants.length > 0) {
                const targetVariant = product.variants.find(v => 
                    (v._id && item.variant._id && v._id.toString() === item.variant._id) || 
                    (v.variety === item.variant.variety && v.color === item.variant.color && v.height === item.variant.height)
                );
                
                if (targetVariant) {
                    availableStock = targetVariant.countInStock;
                    itemName = `${product.name} (${targetVariant.variety} ${targetVariant.color||''} ${targetVariant.height||''})`;
                }
            } else if (product.variants.length > 0) {
                availableStock = product.variants[0].countInStock; 
            } else {
                availableStock = product.countInStock || 0;
            }

            if (availableStock < item.qty) {
                outOfStockItems.push(`${itemName} (Stock: ${availableStock})`);
            }
        }

        if (outOfStockItems.length > 0) {
            return res.status(409).json({ error: "Stock validation failed", outOfStockItems: outOfStockItems });
        }
        res.status(200).json({ message: "Stock available" });
    } catch (error) { res.status(500).json({ error: "Server error checking stock" }); }
});

const uploadFields = upload.fields([{ name: 'image', maxCount: 1 }, { name: 'gallery', maxCount: 3 }]);

app.post('/api/products', authenticateToken, requireAdmin, uploadFields, async (req, res) => {
    try {
        let mainImageUrl = "https://res.cloudinary.com/dvlwzfsd0/image/upload/v1766831829/no_product_jjmm9m.png";
        if (req.files && req.files['image']) mainImageUrl = req.files['image'][0].path;

        let galleryUrls = [];
        if (req.files && req.files['gallery']) galleryUrls = req.files['gallery'].map(file => file.path);

        let variants = [];
        if (req.body.variants) variants = typeof req.body.variants === 'string' ? JSON.parse(req.body.variants) : req.body.variants;

        let basePrice = 0;
        if (variants.length > 0) {
            const prices = variants.map(v => v.price).filter(p => p > 0);
            if (prices.length > 0) basePrice = Math.min(...prices);
        }

        const newProduct = new Product({ ...req.body, imageUrl: mainImageUrl, galleryImages: galleryUrls, variants: variants, basePrice: basePrice });
        await newProduct.save();
        res.status(201).json(newProduct);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/products/:id', authenticateToken, requireAdmin, uploadFields, async (req, res) => {
    try {
        const updateData = { ...req.body };
        if (req.files && req.files['image']) updateData.imageUrl = req.files['image'][0].path;
        if (req.files && req.files['gallery']) updateData.galleryImages = req.files['gallery'].map(file => file.path);
        if (updateData.variants) {
            updateData.variants = typeof updateData.variants === 'string' ? JSON.parse(updateData.variants) : updateData.variants;
            const prices = updateData.variants.map(v => v.price).filter(p => p > 0);
            if (prices.length > 0) updateData.basePrice = Math.min(...prices);
        }
        const updatedProduct = await Product.findByIdAndUpdate(req.params.id, { $set: updateData }, { new: true });
        res.json(updatedProduct);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/products/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.json({ message: "Deleted" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ======================================================
// --- 7. ORDER PROCESSING & PAYMENT (FIXED) ---
// ======================================================

// 1. CREATE PAYMENT ORDER (With Strict Stock & 18% Tax)
app.post('/api/payment/create', async (req, res) => {
    try {
        const { items, orderType } = req.body;
        let calculatedSubtotal = 0;

        for (const item of items) {
            const product = await Product.findById(item.id || item._id);
            if (!product) return res.status(404).json({ error: `Product not found` });

            let priceToUse = product.basePrice || 0;
            let currentStock = 0;
            let variantName = "";

            // --- STRICT VARIANT MATCHING ---
            let targetVariant = null;
            if (item.variant && product.variants.length > 0) {
                targetVariant = product.variants.find(v => {
                    if (v._id && item.variant._id && v._id.toString() === item.variant._id) return true;
                    // Match attributes carefully
                    return (v.variety === item.variant.variety) && 
                           (v.color === item.variant.color) && 
                           (v.height === item.variant.height);
                });
            } else if (product.variants.length > 0) {
                targetVariant = product.variants[0];
            } else {
                currentStock = product.countInStock || 0; // Simple product
                priceToUse = product.basePrice;
            }

            if (targetVariant) {
                priceToUse = targetVariant.price;
                currentStock = targetVariant.countInStock;
                variantName = `(${targetVariant.variety} ${targetVariant.color||''} ${targetVariant.height||''})`;
            }

            if (item.qty > currentStock) {
                return res.status(400).json({ error: `Out of Stock: ${product.name} ${variantName}. Only ${currentStock} left.` });
            }

            calculatedSubtotal += (Number(priceToUse) * Number(item.qty));
        }

        // --- TAX & TOTAL CALCULATION ---
        const taxAmount = calculatedSubtotal * 0.18; // 18% Tax
        let deliveryFee = orderType === 'delivery' ? 40 : 0;
        let finalTotal = Math.round(calculatedSubtotal + taxAmount + deliveryFee);

        if (finalTotal <= 0) return res.status(400).json({ error: "Invalid amount" });

        const options = {
            amount: Math.round(finalTotal * 100), // Paise
            currency: "INR",
            receipt: `receipt_${Date.now()}`
        };

        const order = await razorpay.orders.create(options);
        res.json(order);

    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 2. SAVE ORDER (With Strict Deduction & Tax)
app.post('/api/orders', async (req, res) => {
    try {
        const { items, customerName, customerPhone, orderType, address, paymentStatus, transactionId } = req.body;
        
        let calculatedSubtotal = 0;
        let secureItems = [];
        const shortToken = Math.floor(1000 + Math.random() * 9000).toString();

        for (const item of items) {
            const product = await Product.findById(item.id || item._id);
            if (!product) return res.status(404).json({ error: "Product not found" });

            let priceToUse = product.basePrice || 0;
            let targetVariant = null;
            let variantLabel = "";

            // --- STRICT MATCHING AGAIN ---
            if (item.variant && product.variants.length > 0) {
                targetVariant = product.variants.find(v => {
                    if (v._id && item.variant._id && v._id.toString() === item.variant._id) return true;
                    return (v.variety === item.variant.variety) && 
                           (v.color === item.variant.color) && 
                           (v.height === item.variant.height);
                });
            } else if (product.variants.length > 0) {
                targetVariant = product.variants[0];
            }

            // Deduct Stock
            if (targetVariant) {
                if (targetVariant.countInStock < item.qty) return res.status(400).json({ error: `Stock changed: ${product.name} is now out of stock.` });
                targetVariant.countInStock -= item.qty;
                priceToUse = targetVariant.price || 0;
                variantLabel = ` - ${targetVariant.variety} ${targetVariant.color||''} ${targetVariant.height||''}`;
            } else {
                if (product.countInStock < item.qty) return res.status(400).json({ error: `Stock changed: ${product.name}` });
                product.countInStock -= item.qty;
            }

            await product.save();

            calculatedSubtotal += (Number(priceToUse) * Number(item.qty));
            secureItems.push({
                product: product._id,
                name: `${product.name}${variantLabel}`,
                qty: item.qty,
                price: priceToUse
            });
        }

        // --- TAX & TOTAL CALCULATION ---
        const taxAmount = calculatedSubtotal * 0.18;
        let deliveryFee = orderType === 'delivery' ? 40 : 0;
        let finalTotal = Math.round(calculatedSubtotal + taxAmount + deliveryFee);

        let finalStatus = 'DUE';
        let finalTxnId = '';

        if (paymentStatus === 'PAID' && transactionId) {
            try {
                const payment = await razorpay.payments.fetch(transactionId);
                if (payment.status === 'captured') {
                    // Verify amount (allow 2 INR variance for rounding)
                    if (Math.abs(payment.amount - (finalTotal * 100)) > 200) {
                        return res.status(400).json({ error: "Payment amount mismatch." });
                    }
                    finalStatus = 'PAID';
                    finalTxnId = transactionId;
                } else {
                    return res.status(400).json({ error: "Payment not captured." });
                }
            } catch (err) {
                return res.status(400).json({ error: "Payment Verification Failed" });
            }
        }

        const newOrder = new Order({
            shortToken, customerName, customerPhone, orderType, address,
            items: secureItems, 
            subtotal: calculatedSubtotal,
            taxAmount: taxAmount,
            deliveryFee: deliveryFee,
            totalAmount: finalTotal,
            paymentStatus: finalStatus, transactionId: finalTxnId, isCollected: false
        });

        await newOrder.save();
        res.status(201).json({ success: true, order: newOrder });

    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- PUBLIC: UPDATE PAYMENT STATUS (For Tracking Page) ---
app.put('/api/orders/update-payment', async (req, res) => {
    try {
        const { orderId, paymentId, status } = req.body;

        // 1. Find the order
        const order = await Order.findById(orderId);
        if (!order) return res.status(404).json({ error: "Order not found" });

        // 2. Update status
        order.paymentStatus = status; // 'PAID'
        order.transactionId = paymentId;
        
        // 3. Save
        await order.save();

        res.json({ success: true, message: "Payment updated", order });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/orders',authenticateToken, requireAdmin, async (req, res) => {
    try {
        const orders = await Order.find().sort({ createdAt: -1 });
        res.json(orders);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/orders/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const updatedOrder = await Order.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true });
        res.json(updatedOrder);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/orders/collect/:id', async (req, res) => {
    try {
        const order = await Order.findByIdAndUpdate(req.params.id, { isCollected: true }, { new: true });
        res.json({ success: true, order });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/orders/track/:phone', async (req, res) => {
    try {
        const orders = await Order.find({ customerPhone: req.params.phone }).sort({ createdAt: -1 }); 
        if (!orders || orders.length === 0) return res.status(404).json({ error: "No orders found" });
        res.json(orders);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/payment/verify', async (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
        const body = razorpay_order_id + "|" + razorpay_payment_id;
        const expectedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(body.toString()).digest('hex');

        if (expectedSignature === razorpay_signature) res.json({ success: true, message: "Payment Verified" });
        else res.status(400).json({ success: false, error: "Invalid Signature" });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ======================================================
// --- 8. SECURE PDF INVOICE GENERATION (WITH TAX) ---
// ======================================================
app.get('/api/orders/:id/invoice', async (req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        if(!order) return res.status(404).send("Order not found");

        const htmlContent = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <style>body { font-family: 'Plus Jakarta Sans', sans-serif; }</style>
        </head>
        <body class="p-8 bg-white text-slate-900">
            <div class="max-w-md mx-auto border border-gray-200 rounded-2xl overflow-hidden shadow-sm">
                <div class="bg-emerald-50 p-6 text-center border-b border-emerald-100">
                    <h1 class="text-2xl font-bold text-emerald-900 mb-1">TARAaang Landscape</h1>
                    <p class="text-xs text-emerald-600 uppercase font-bold tracking-wider">Official Invoice</p>
                    <div class="mt-4 inline-block bg-white px-4 py-1 rounded-full border border-emerald-100">
                        <span class="text-xs text-gray-400 font-bold uppercase">Token:</span>
                        <span class="text-xl font-black text-slate-800">#${order.shortToken}</span>
                    </div>
                </div>

                <div class="p-6">
                    <div class="space-y-2 text-sm mb-6">
                        <div class="flex justify-between border-b border-gray-50 pb-2"><span class="text-gray-500">Customer</span><span class="font-bold">${order.customerName}</span></div>
                        <div class="flex justify-between border-b border-gray-50 pb-2"><span class="text-gray-500">Phone</span><span class="font-bold">${order.customerPhone}</span></div>
                        <div class="flex justify-between border-b border-gray-50 pb-2"><span class="text-gray-500">Date</span><span class="font-bold">${new Date(order.createdAt).toLocaleDateString()}</span></div>
                        <div class="flex justify-between border-b border-gray-50 pb-2"><span class="text-gray-500">Status</span>
                            <span class="font-bold uppercase ${order.paymentStatus === 'PAID' ? 'text-emerald-600' : 'text-orange-600'}">
                                ${order.paymentStatus === 'PAID' ? 'PAID (Online)' : 'DUE (Cash/Later)'}
                            </span>
                        </div>
                    </div>

                    <div class="bg-gray-50 rounded-xl p-4 mb-6">
                        <h3 class="text-xs font-bold text-gray-400 uppercase mb-3">Items Purchased</h3>
                        <div class="space-y-3">
                            ${order.items.map(item => `
                                <div class="flex justify-between text-sm">
                                    <div class="w-3/4">
                                        <span class="font-bold text-gray-800">${item.qty}x</span> 
                                        <span class="text-gray-600">${item.name}</span>
                                    </div>
                                    <div class="font-bold text-gray-900">₹${(item.price * item.qty).toLocaleString()}</div>
                                </div>
                            `).join('')}
                        </div>
                        
                        <div class="h-px bg-gray-200 my-4"></div>
                        
                        <div class="space-y-1 text-xs text-gray-600">
                            <div class="flex justify-between"><span>Subtotal</span><span>₹${(order.subtotal || 0).toLocaleString()}</span></div>
                            <div class="flex justify-between"><span>Service Tax (18%)</span><span>₹${(order.taxAmount || 0).toLocaleString()}</span></div>
                            ${order.deliveryFee > 0 ? `<div class="flex justify-between"><span>Delivery Fee</span><span>₹${order.deliveryFee}</span></div>` : ''}
                        </div>
                    </div>

                    <div class="flex justify-between items-center bg-slate-900 text-white p-4 rounded-xl">
                        <span class="text-sm font-medium text-slate-300">Total Amount</span>
                        <span class="text-2xl font-bold">₹${order.totalAmount.toLocaleString()}</span>
                    </div>
                    
                    <div class="mt-6 text-center text-[10px] text-gray-400">
                        <p>Thank you for shopping with TARAaang!</p>
                        <p>Order ID: ${order._id}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        `;

        const browser = await puppeteer.launch({ args: ['--no-sandbox', '--disable-setuid-sandbox'] });
        const page = await browser.newPage();
        await page.setContent(htmlContent, { waitUntil: 'networkidle0' });
        const pdfBuffer = await page.pdf({ format: 'A4', printBackground: true, margin: { top: '20px', bottom: '20px' } });
        await browser.close();

        res.set({
            'Content-Type': 'application/pdf',
            'Content-Disposition': `attachment; filename=Invoice_${order.customerName}_${order.shortToken}.pdf`,
            'Content-Length': pdfBuffer.length
        });
        res.send(pdfBuffer);

    } catch (e) {
        console.error("PDF Gen Error:", e);
        res.status(500).send("Error generating invoice");
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));