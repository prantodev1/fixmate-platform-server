const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { connectDB } = require("./config/db");
const Service = require("./models/Service");
const User = require("./models/User");
const Booking = require("./models/Booking");
const Payment = require("./models/Payment");
const ContactMessage = require("./models/ContactMessage");

const app = express();
const port = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "fixmate_secret_key";
const FREE_PLAN_SERVICE_LIMIT = 3;
const PRO_PLAN_MONTHLY_PRICE = Number(process.env.PRO_PLAN_PRICE || 19);
const DEFAULT_SERVICES_LIMIT = 8;
const MAX_SERVICES_LIMIT = 50;

let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  try {
    stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
  } catch (err) {
    console.warn("Stripe SDK not initialized:", err.message);
  }
}

const allowedOrigins = [
  "http://localhost:3000",
  process.env.CLIENT_URL,
].filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized: No token provided",
    });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = {
      ...decoded,
      role: (decoded?.role || "").toString().toLowerCase().trim(),
    };
    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: "Unauthorized: Invalid or expired token",
    });
  }
};

const verifyCustomer = (req, res, next) => {
  if (req.user?.role !== "customer") {
    return res.status(403).json({
      success: false,
      message: "Forbidden: Customer access required",
    });
  }
  next();
};

const verifyTechnician = (req, res, next) => {
  if (req.user?.role !== "technician") {
    return res.status(403).json({
      success: false,
      message: "Forbidden: Technician access required",
    });
  }
  next();
};

const verifyAdmin = (req, res, next) => {
  if (req.user?.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Forbidden: Admin access required",
    });
  }
  next();
};

function escapeRegex(value = "") {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeUserPlan(plan) {
  return String(plan || "free").toLowerCase().trim() === "pro" ? "pro" : "free";
}

function formatSafeUser(user) {
  const plan = normalizeUserPlan(user?.plan);
  return {
    _id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    plan,
    isVerifiedPro: user.role === "technician" && plan === "pro",
    proActivatedAt: user.proActivatedAt || null,
    avatar: user.avatar || "",
    phone: user.phone || "",
    area: user.area || "",
    bio: user.bio || "",
    createdAt: user.createdAt || null,
  };
}

function normalizeStatusStep(statusValue) {
  const raw = String(statusValue || "")
    .toLowerCase()
    .trim();
  if (raw === "in progress") return "in-progress";
  return raw;
}

function buildStatusHistory(bookingLike = {}) {
  const rawHistory = Array.isArray(bookingLike?.statusHistory)
    ? bookingLike.statusHistory
    : [];

  const normalizedEntries = [];
  for (const entry of rawHistory) {
    if (!entry) continue;
    const step = normalizeStatusStep(
      typeof entry === "string" ? entry : entry.status
    );
    if (!step) continue;
    const timestamp =
      (typeof entry === "object" && entry.changedAt) ||
      bookingLike.updatedAt ||
      bookingLike.createdAt ||
      new Date();
    normalizedEntries.push({
      status: step,
      changedAt: timestamp,
    });
  }

  const baseTime = bookingLike.createdAt || new Date();
  const currentStatus = normalizeStatusStep(bookingLike.status || "requested");
  const isPaid =
    String(bookingLike.paymentStatus || "")
      .toLowerCase()
      .trim() === "paid";

  const hasRequested = normalizedEntries.some(
    (e) => e.status === "requested"
  );
  if (!hasRequested) {
    normalizedEntries.unshift({
      status: "requested",
      changedAt: baseTime,
    });
  }

  const progressionOrder = [
    "requested",
    "accepted",
    "in-progress",
    "completed",
  ];
  const currentIndex = progressionOrder.indexOf(currentStatus);

  if (currentIndex > 0) {
    for (let i = 1; i <= currentIndex; i++) {
      const targetStep = progressionOrder[i];
      const alreadyExists = normalizedEntries.some(
        (e) => e.status === targetStep
      );
      if (!alreadyExists) {
        normalizedEntries.push({
          status: targetStep,
          changedAt:
            targetStep === currentStatus
              ? bookingLike.updatedAt || new Date()
              : bookingLike.updatedAt || baseTime,
        });
      }
    }
  }

  if (
    currentStatus &&
    !progressionOrder.includes(currentStatus) &&
    !normalizedEntries.some((e) => e.status === currentStatus)
  ) {
    normalizedEntries.push({
      status: currentStatus,
      changedAt: bookingLike.updatedAt || new Date(),
    });
  }

  if (isPaid && !normalizedEntries.some((e) => e.status === "paid")) {
    normalizedEntries.push({
      status: "paid",
      changedAt:
        bookingLike.paidAt || bookingLike.updatedAt || new Date(),
    });
  }

  return normalizedEntries;
}

async function appendBookingStatusHistory(bookingId, statusValue, changedAt = new Date()) {
  const step = normalizeStatusStep(statusValue);
  if (!bookingId || !step) return;

  await Booking.collection.updateOne(
    { _id: bookingId },
    {
      $push: {
        statusHistory: {
          status: step,
          changedAt,
        },
      },
      $set: {
        updatedAt: changedAt,
      },
    }
  );
}

function normalizeBookingRecord(booking) {
  const obj =
    typeof booking?.toObject === "function"
      ? booking.toObject({ getters: true })
      : { ...booking };

  const numericRating = Number(
    obj?.rating ?? obj?.reviewRating ?? obj?.stars ?? 0
  );
  const hasValidRating =
    Number.isFinite(numericRating) && numericRating >= 1 && numericRating <= 5;
  const reviewText = String(
    obj?.review ?? obj?.reviewText ?? obj?.comment ?? ""
  ).trim();

  return {
    ...obj,
    rating: hasValidRating ? Math.round(numericRating) : null,
    review: reviewText,
    reviewedAt: obj?.reviewedAt || null,
    statusHistory: buildStatusHistory(obj),
  };
}

async function mapCustomersByBookingRecords(records = []) {
  const customerIds = new Set();
  const customerEmails = new Set();

  for (const r of records) {
    if (r?.customerId) customerIds.add(String(r.customerId));
    if (r?.customerEmail) {
      customerEmails.add(String(r.customerEmail).toLowerCase().trim());
    }
  }

  const orConditions = [];
  if (customerIds.size > 0) {
    orConditions.push({ _id: { $in: Array.from(customerIds) } });
  }
  if (customerEmails.size > 0) {
    orConditions.push({ email: { $in: Array.from(customerEmails) } });
  }

  const usersById = new Map();
  const usersByEmail = new Map();

  if (orConditions.length > 0) {
    const customers = await User.find({ $or: orConditions }).select(
      "_id name email avatar"
    );
    for (const u of customers) {
      usersById.set(String(u._id), u);
      if (u.email) {
        usersByEmail.set(String(u.email).toLowerCase().trim(), u);
      }
    }
  }

  return { usersById, usersByEmail };
}

async function recalculateServiceRating(serviceId) {
  if (!serviceId) return null;

  const rawReviewedBookings = await Booking.collection
    .find({
      serviceId,
      rating: { $gte: 1, $lte: 5 },
    })
    .sort({ reviewedAt: -1, updatedAt: -1, createdAt: -1 })
    .toArray();

  const reviewedBookings = rawReviewedBookings.map(normalizeBookingRecord);
  const { usersById, usersByEmail } =
    await mapCustomersByBookingRecords(reviewedBookings);

  const reviewCount = reviewedBookings.length;
  const sum = reviewedBookings.reduce(
    (acc, item) => acc + Number(item.rating || 0),
    0
  );
  const averageRating =
    reviewCount > 0 ? Number((sum / reviewCount).toFixed(1)) : 0;

  const reviews = reviewedBookings.map((item) => {
    const matchedCustomer =
      (item.customerId && usersById.get(String(item.customerId))) ||
      (item.customerEmail &&
        usersByEmail.get(String(item.customerEmail).toLowerCase().trim())) ||
      null;

    const customerImage =
      matchedCustomer?.avatar || item.customerImage || item.customerAvatar || "";

    return {
      _id: item._id,
      rating: Number(item.rating),
      review: String(item.review || "").trim(),
      customerName:
        matchedCustomer?.name || item.customerName || "Customer",
      customerImage,
      customerAvatar: customerImage,
      reviewedAt: item.reviewedAt || item.updatedAt || item.createdAt,
    };
  });

  await Service.findByIdAndUpdate(serviceId, {
    $set: {
      averageRating,
      reviewCount,
    },
  });

  return {
    averageRating,
    reviewCount,
    reviews,
  };
}

async function attachRatingsToServices(services = []) {
  if (!Array.isArray(services) || services.length === 0) {
    return [];
  }

  const serviceIds = services
    .map((s) =>
      typeof s?.toObject === "function" ? s.toObject()._id : s?._id
    )
    .filter(Boolean);

  if (serviceIds.length === 0) {
    return services;
  }

  const reviewedBookings = await Booking.collection
    .find({
      serviceId: { $in: serviceIds },
      rating: { $gte: 1, $lte: 5 },
    })
    .toArray();

  const statsMap = new Map();
  for (const b of reviewedBookings) {
    const key = String(b.serviceId);
    const current = statsMap.get(key) || { sum: 0, count: 0 };
    current.sum += Number(b.rating || 0);
    current.count += 1;
    statsMap.set(key, current);
  }

  return services.map((srv) => {
    const obj =
      typeof srv?.toObject === "function" ? srv.toObject() : { ...srv };
    const stat = statsMap.get(String(obj._id));
    const reviewCount = stat ? stat.count : Number(obj.reviewCount || 0);
    const averageRating =
      stat && stat.count > 0
        ? Number((stat.sum / stat.count).toFixed(1))
        : Number(obj.averageRating || 0);

    return {
      ...obj,
      averageRating,
      reviewCount,
    };
  });
}

async function findTechnicianUserRecord(record = {}) {
  const orConditions = [];
  if (record?.technicianId) {
    orConditions.push({ _id: record.technicianId });
  }
  if (record?.technicianEmail) {
    const cleanEmail = String(record.technicianEmail).toLowerCase().trim();
    if (cleanEmail) {
      orConditions.push({ email: cleanEmail });
    }
  }

  if (orConditions.length === 0) {
    return null;
  }

  return User.findOne({ $or: orConditions }).select(
    "_id name email avatar area bio phone role plan"
  );
}

async function fetchUsersByIdAndEmail(records = []) {
  const techIds = new Set();
  const techEmails = new Set();

  for (const item of records) {
    if (item?.technicianId) {
      techIds.add(String(item.technicianId));
    }
    if (item?.technicianEmail) {
      techEmails.add(String(item.technicianEmail).toLowerCase().trim());
    }
  }

  const orQuery = [];
  if (techIds.size > 0) {
    orQuery.push({ _id: { $in: Array.from(techIds) } });
  }
  if (techEmails.size > 0) {
    orQuery.push({ email: { $in: Array.from(techEmails) } });
  }

  const usersById = new Map();
  const usersByEmail = new Map();

  if (orQuery.length > 0) {
    const techUsers = await User.find({ $or: orQuery }).select(
      "_id name email avatar area bio phone role plan"
    );
    for (const u of techUsers) {
      usersById.set(String(u._id), u);
      if (u.email) {
        usersByEmail.set(String(u.email).toLowerCase().trim(), u);
      }
    }
  }

  return { usersById, usersByEmail };
}

async function attachLatestTechnicianNames(services = []) {
  if (!Array.isArray(services) || services.length === 0) {
    return [];
  }

  const { usersById, usersByEmail } = await fetchUsersByIdAndEmail(services);

  return services.map((srv) => {
    const obj =
      typeof srv?.toObject === "function" ? srv.toObject() : { ...srv };
    const idKey = obj.technicianId ? String(obj.technicianId) : "";
    const emailKey = obj.technicianEmail
      ? String(obj.technicianEmail).toLowerCase().trim()
      : "";

    const matchedUser =
      (idKey && usersById.get(idKey)) ||
      (emailKey && usersByEmail.get(emailKey)) ||
      null;

    const latestName =
      matchedUser?.name ||
      obj.technician?.name ||
      obj.technicianName ||
      "Verified Technician";
    const techPlan = normalizeUserPlan(matchedUser?.plan || obj.technicianPlan);
    const isVerifiedPro = techPlan === "pro";

    return {
      ...obj,
      technicianName: latestName,
      technicianPlan: techPlan,
      isVerifiedPro,
      technician: {
        ...(obj.technician && typeof obj.technician === "object"
          ? obj.technician
          : {}),
        _id: matchedUser?._id || obj.technicianId || null,
        name: latestName,
        email: matchedUser?.email || obj.technicianEmail || "",
        avatar: matchedUser?.avatar || obj.technician?.avatar || "",
        area: matchedUser?.area || obj.area || "",
        bio: matchedUser?.bio || obj.technician?.bio || "",
        plan: techPlan,
        isVerifiedPro,
      },
    };
  });
}

async function attachLatestTechnicianNamesToBookings(bookings = []) {
  if (!Array.isArray(bookings) || bookings.length === 0) {
    return [];
  }

  const { usersById, usersByEmail } = await fetchUsersByIdAndEmail(bookings);

  return bookings.map((booking) => {
    const obj = normalizeBookingRecord(booking);
    const idKey = obj.technicianId ? String(obj.technicianId) : "";
    const emailKey = obj.technicianEmail
      ? String(obj.technicianEmail).toLowerCase().trim()
      : "";

    const matchedUser =
      (idKey && usersById.get(idKey)) ||
      (emailKey && usersByEmail.get(emailKey)) ||
      null;

    const latestName =
      matchedUser?.name ||
      obj.technician?.name ||
      obj.technicianName ||
      "Technician";
    const techPlan = normalizeUserPlan(matchedUser?.plan || obj.technicianPlan);
    const isVerifiedPro = techPlan === "pro";

    return {
      ...obj,
      technicianName: latestName,
      technicianPlan: techPlan,
      isVerifiedPro,
      technician: {
        ...(obj.technician && typeof obj.technician === "object"
          ? obj.technician
          : {}),
        _id: matchedUser?._id || obj.technicianId || null,
        name: latestName,
        email: matchedUser?.email || obj.technicianEmail || "",
        phone: matchedUser?.phone || obj.technicianPhone || "",
        area: matchedUser?.area || obj.technicianArea || "",
        bio: matchedUser?.bio || obj.technician?.bio || "",
        plan: techPlan,
        isVerifiedPro,
      },
    };
  });
}

app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FixMate API Server</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
            body { background-color: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; overflow: hidden; }
            .card { background: #1e293b; padding: 40px; border-radius: 16px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5); text-align: center; max-width: 550px; width: 100%; border: 1px solid #334155; }
            .logo { font-size: 32px; font-weight: 700; color: #38bdf8; margin-bottom: 10px; display: flex; align-items: center; justify-content: center; gap: 12px; }
            .logo-icon { width: 42px; height: 42px; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 12px; display: flex; align-items: center; justify-content: center; box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.2); }
            .logo-icon svg { width: 22px; height: 22px; stroke: #38bdf8; fill: none; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }
            .status-badge { display: inline-flex; align-items: center; gap: 8px; background: rgba(34, 197, 94, 0.1); color: #4ade80; padding: 6px 16px; border-radius: 50px; font-size: 14px; font-weight: 600; margin-bottom: 20px; border: 1px solid rgba(34, 197, 94, 0.2); }
            .pulse { width: 10px; height: 10px; background: #4ade80; border-radius: 50%; box-shadow: 0 0 0 0 rgba(74, 222, 128, 0.7); animation: pulse 1.5s infinite; }
            @keyframes pulse { 0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(74, 222, 128, 0.7); } 70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(74, 222, 128, 0); } 100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(74, 222, 128, 0); } }
            p { color: #94a3b8; font-size: 15px; margin-bottom: 25px; line-height: 1.5; }
            .endpoints { background: #0f172a; padding: 15px; border-radius: 8px; text-align: left; font-family: monospace; font-size: 13px; color: #38bdf8; border: 1px solid #334155; }
            .endpoints span { color: #cbd5e1; }
            .footer { margin-top: 25px; font-size: 12px; color: #64748b; }
        </style>
    </head>
    <body>
        <div class="card">
            <div class="logo">
                <div class="logo-icon">
                    <svg viewBox="0 0 24 24"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"></path></svg>
                </div>
                <span>Fix<span style="color: #ffffff;">Mate</span> API</span>
            </div>
            <div>
                <span class="status-badge">
                    <span class="pulse"></span> Server is Live & Connected
                </span>
            </div>
            <p>Welcome to the official backend engine of FixMate On-Demand Device & Home Appliance Repair Service Platform.</p>
            <div class="endpoints">
                <strong>Base URL:</strong> http://localhost:5000<br>
                <strong>Status Route:</strong> <span>GET /</span><br>
                <strong>Environment:</strong> <span>Development (Node.js)</span>
            </div>
            <div class="footer">Powered by Next.js & Express.js Core • Secure & Fast</div>
        </div>
    </body>
    </html>
  `);
});

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    const normalizedEmail = String(email).toLowerCase().trim();
    const assignedRole = role === "technician" ? "technician" : "customer";

    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists with this email",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      name: String(name).trim(),
      email: normalizedEmail,
      password: hashedPassword,
      role: assignedRole,
      plan: "free",
    });

    const token = jwt.sign(
      { userId: newUser._id, email: newUser.email, role: newUser.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(201).json({
      success: true,
      message: "Account created successfully",
      token,
      user: formatSafeUser(newUser),
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    if (!user.password) {
      return res.status(400).json({
        success: false,
        message:
          "This account uses Google sign-in. Please continue with Google.",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(200).json({
      success: true,
      message: "Logged in successfully",
      token,
      user: formatSafeUser(user),
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
});

app.post("/api/auth/google", async (req, res) => {
  try {
    const { access_token, role } = req.body;

    if (!access_token) {
      return res.status(400).json({
        success: false,
        message: "Google access token is required",
      });
    }

    const googleRes = await fetch(
      "https://www.googleapis.com/oauth2/v3/userinfo",
      {
        headers: { Authorization: `Bearer ${access_token}` },
      }
    );

    if (!googleRes.ok) {
      return res.status(401).json({
        success: false,
        message: "Invalid Google token",
      });
    }

    const googleUser = await googleRes.json();
    const { sub, email, name, picture } = googleUser;
    const normalizedEmail = String(email || "").toLowerCase().trim();

    let user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      const assignedRole = role === "technician" ? "technician" : "customer";
      user = await User.create({
        name,
        email: normalizedEmail,
        googleId: sub,
        avatar: picture || "",
        role: assignedRole,
        plan: "free",
      });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(200).json({
      success: true,
      message: "Signed in with Google successfully",
      token,
      user: formatSafeUser(user),
    });
  } catch (error) {
    console.error("Google auth error:", error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
});

app.get("/api/auth/me", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    res.status(200).json({
      success: true,
      user: formatSafeUser(user),
    });
  } catch (error) {
    console.error("Get profile error:", error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
});

async function updateUserProfileHandler(req, res) {
  try {
    const { name, phone, area, bio, avatar } = req.body;

    if (!name || !String(name).trim()) {
      return res.status(400).json({
        success: false,
        message: "Full name is required",
      });
    }

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const trimmedName = String(name).trim();
    user.name = trimmedName;
    if (phone !== undefined) user.phone = String(phone).trim();
    if (area !== undefined) user.area = String(area).trim();
    if (bio !== undefined) user.bio = String(bio).trim();
    if (avatar !== undefined) user.avatar = avatar;

    await user.save();

    const normalizedEmail = String(user.email || "").toLowerCase().trim();
    const ownerFilter = {
      $or: [
        { technicianId: user._id },
        ...(normalizedEmail ? [{ technicianEmail: normalizedEmail }] : []),
      ],
    };

    await Promise.all([
      Service.updateMany(ownerFilter, { $set: { technicianName: trimmedName } }),
      Booking.updateMany(ownerFilter, { $set: { technicianName: trimmedName } }),
    ]);

    res.status(200).json({
      success: true,
      message: "Profile updated successfully",
      user: formatSafeUser(user),
    });
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
}

app.patch("/api/users/profile", verifyToken, updateUserProfileHandler);
app.patch("/api/auth/profile", verifyToken, updateUserProfileHandler);

async function activateTechnicianProPlan(user, meta = {}) {
  const transactionId =
    meta.transactionId ||
    `sub_${Date.now().toString(36).toUpperCase()}${Math.random()
      .toString(36)
      .substring(2, 6)
      .toUpperCase()}`;

  if (meta.stripeSessionId) {
    const existingPayment = await Payment.findOne({
      stripeSessionId: meta.stripeSessionId,
      status: "paid",
    });
    if (existingPayment) {
      return { user, payment: existingPayment, alreadyRecorded: true };
    }
  }

  user.plan = "pro";
  user.proActivatedAt = user.proActivatedAt || new Date();
  if (meta.stripeCustomerId) user.stripeCustomerId = meta.stripeCustomerId;
  if (meta.stripeSubscriptionId) {
    user.stripeSubscriptionId = meta.stripeSubscriptionId;
  }
  await user.save();

  const payment = await Payment.create({
    type: "subscription",
    plan: "pro",
    serviceTitle: "Pro Technician Plan (Monthly)",
    userId: user._id,
    userName: user.name,
    userEmail: user.email,
    userRole: user.role,
    amount: Number(meta.amount ?? PRO_PLAN_MONTHLY_PRICE),
    currency: "usd",
    provider: "stripe",
    transactionId,
    stripeSessionId: meta.stripeSessionId || undefined,
    stripeSubscriptionId:
      meta.stripeSubscriptionId || user.stripeSubscriptionId || "",
    status: "paid",
    paidAt: new Date(),
  });

  return { user, payment, alreadyRecorded: false };
}

app.get(
  "/api/subscriptions/pro/status",
  verifyToken,
  verifyTechnician,
  async (req, res) => {
    try {
      const user = await User.findById(req.user.userId).select("-password");
      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Technician not found",
        });
      }

      const normalizedEmail = String(user.email || "").toLowerCase().trim();
      const serviceCount = await Service.countDocuments({
        $or: [
          { technicianId: user._id },
          ...(normalizedEmail ? [{ technicianEmail: normalizedEmail }] : []),
        ],
      });

      const plan = normalizeUserPlan(user.plan);
      const isPro = plan === "pro";

      res.status(200).json({
        success: true,
        plan,
        isVerifiedPro: isPro,
        serviceCount,
        serviceLimit: isPro ? null : FREE_PLAN_SERVICE_LIMIT,
        remainingFreeSlots: isPro
          ? null
          : Math.max(0, FREE_PLAN_SERVICE_LIMIT - serviceCount),
        price: PRO_PLAN_MONTHLY_PRICE,
        proActivatedAt: user.proActivatedAt || null,
        user: formatSafeUser(user),
      });
    } catch (error) {
      console.error("Error fetching Pro subscription status:", error);
      res.status(500).json({
        success: false,
        message: "Internal Server Error",
      });
    }
  }
);

app.post(
  "/api/subscriptions/pro/checkout-session",
  verifyToken,
  verifyTechnician,
  async (req, res) => {
    try {
      const user = await User.findById(req.user.userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Technician account not found",
        });
      }

      if (normalizeUserPlan(user.plan) === "pro") {
        return res.status(200).json({
          success: true,
          alreadyPro: true,
          message: "You are already subscribed to the Pro Technician Plan.",
          user: formatSafeUser(user),
        });
      }

      const clientBaseUrl = (
        req.body?.returnUrl ||
        process.env.CLIENT_URL ||
        "http://localhost:3000"
      ).replace(/\/+$/, "");

      if (stripe && process.env.STRIPE_PRO_PRICE_ID) {
        const session = await stripe.checkout.sessions.create({
          mode: "subscription",
          payment_method_types: ["card"],
          customer_email: user.email,
          line_items: [
            {
              price: process.env.STRIPE_PRO_PRICE_ID,
              quantity: 1,
            },
          ],
          metadata: {
            userId: String(user._id),
            userEmail: user.email,
            plan: "pro",
          },
          success_url: `${clientBaseUrl}/dashboard/technician/my-services?upgrade=success&session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${clientBaseUrl}/dashboard/technician/my-services?upgrade=cancelled`,
        });

        return res.status(200).json({
          success: true,
          mode: "stripe",
          sessionId: session.id,
          url: session.url,
        });
      }

      const { payment } = await activateTechnicianProPlan(user, {
        amount: PRO_PLAN_MONTHLY_PRICE,
      });

      return res.status(200).json({
        success: true,
        mode: "direct",
        message:
          "Upgraded to Pro Technician Plan! Unlimited services & Verified Pro badge unlocked.",
        transactionId: payment.transactionId,
        payment,
        user: formatSafeUser(user),
      });
    } catch (error) {
      console.error("Pro checkout session error:", error);
      res.status(500).json({
        success: false,
        message: error?.message || "Failed to initiate Pro subscription.",
      });
    }
  }
);

app.post(
  "/api/subscriptions/pro/confirm",
  verifyToken,
  verifyTechnician,
  async (req, res) => {
    try {
      const { sessionId } = req.body || {};
      const user = await User.findById(req.user.userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Technician account not found",
        });
      }

      const stripeCheckoutEnabled = Boolean(
        stripe && process.env.STRIPE_PRO_PRICE_ID
      );

      if (stripeCheckoutEnabled) {
        if (!sessionId) {
          return res.status(400).json({
            success: false,
            message: "Missing Stripe checkout session id.",
          });
        }

        const session = await stripe.checkout.sessions.retrieve(sessionId);
        const sessionUserId = String(session.metadata?.userId || "").trim();
        const sessionUserEmail = String(
          session.customer_email || session.metadata?.userEmail || ""
        )
          .toLowerCase()
          .trim();

        if (
          (sessionUserId && sessionUserId !== String(user._id)) ||
          (!sessionUserId &&
            sessionUserEmail &&
            sessionUserEmail !== String(user.email).toLowerCase().trim())
        ) {
          return res.status(403).json({
            success: false,
            message: "This checkout session belongs to another account.",
          });
        }

        if (
          session.payment_status !== "paid" &&
          session.status !== "complete"
        ) {
          return res.status(400).json({
            success: false,
            message: "Stripe subscription payment is not completed yet.",
          });
        }

        const amountTotal = session.amount_total
          ? Number(session.amount_total) / 100
          : PRO_PLAN_MONTHLY_PRICE;

        const { payment } = await activateTechnicianProPlan(user, {
          amount: amountTotal,
          stripeSessionId: session.id,
          stripeCustomerId:
            typeof session.customer === "string" ? session.customer : "",
          stripeSubscriptionId:
            typeof session.subscription === "string"
              ? session.subscription
              : "",
          transactionId:
            typeof session.subscription === "string"
              ? session.subscription
              : session.id,
        });

        return res.status(200).json({
          success: true,
          message: "Pro Technician Plan activated successfully.",
          payment,
          user: formatSafeUser(user),
        });
      }

      if (normalizeUserPlan(user.plan) === "pro") {
        return res.status(200).json({
          success: true,
          message: "Pro Technician Plan is active.",
          user: formatSafeUser(user),
        });
      }

      const { payment } = await activateTechnicianProPlan(user, {
        amount: PRO_PLAN_MONTHLY_PRICE,
      });

      return res.status(200).json({
        success: true,
        message: "Pro Technician Plan activated successfully.",
        payment,
        user: formatSafeUser(user),
      });
    } catch (error) {
      console.error("Confirm Pro subscription error:", error);
      res.status(500).json({
        success: false,
        message: "Internal Server Error",
      });
    }
  }
);

app.get("/api/services", async (req, res) => {
  try {
    const { search, q, category, mode, sort, page, limit } = req.query;
    const andConditions = [
      {
        $and: [
          {
            $or: [
              {
                status: {
                  $regex: "^(approved|active|published)$",
                  $options: "i",
                },
              },
              { status: { $exists: false } },
              { status: null },
              { status: "" },
            ],
          },
          {
            $or: [
              {
                approvalStatus: {
                  $regex: "^(approved|active|published)$",
                  $options: "i",
                },
              },
              { approvalStatus: { $exists: false } },
              { approvalStatus: null },
              { approvalStatus: "" },
            ],
          },
        ],
      },
      {
        $and: [
          {
            $or: [
              { available: { $ne: false } },
              { available: { $exists: false } },
            ],
          },
          {
            $or: [
              { isAvailable: { $ne: false } },
              { isAvailable: { $exists: false } },
            ],
          },
        ],
      },
    ];

    const trimmedCategory = (category || "").toString().trim();
    if (trimmedCategory && trimmedCategory.toLowerCase() !== "all") {
      const catLower = trimmedCategory.toLowerCase();
      if (catLower === "ac" || catLower.includes("ac & refrigeration")) {
        andConditions.push({
          category: {
            $regex: "(ac|refrigerator|fridge|cooling)",
            $options: "i",
          },
        });
      } else {
        andConditions.push({
          category: {
            $regex: `^${escapeRegex(trimmedCategory)}$`,
            $options: "i",
          },
        });
      }
    }

    const trimmedMode = (mode || "").toString().trim();
    if (trimmedMode && trimmedMode.toLowerCase() !== "all") {
      andConditions.push({
        $or: [
          { mode: { $regex: `^${escapeRegex(trimmedMode)}$`, $options: "i" } },
          {
            serviceMode: {
              $regex: `^${escapeRegex(trimmedMode)}$`,
              $options: "i",
            },
          },
        ],
      });
    }

    const searchText = (search || q || "").toString().trim();
    if (searchText) {
      const safePattern = escapeRegex(searchText);
      andConditions.push({
        $or: [
          { title: { $regex: safePattern, $options: "i" } },
          { category: { $regex: safePattern, $options: "i" } },
          { technicianName: { $regex: safePattern, $options: "i" } },
          { area: { $regex: safePattern, $options: "i" } },
          { description: { $regex: safePattern, $options: "i" } },
        ],
      });
    }

    let sortOption = { createdAt: -1, _id: -1 };
    if (sort === "price-asc") {
      sortOption = { price: 1, createdAt: -1, _id: -1 };
    } else if (sort === "price-desc") {
      sortOption = { price: -1, createdAt: -1, _id: -1 };
    } else if (sort === "newest") {
      sortOption = { createdAt: -1, _id: -1 };
    }

    const queryFilter = { $and: andConditions };

    const parsedLimit = Number.parseInt(limit, 10);
    const safeLimit =
      Number.isFinite(parsedLimit) && parsedLimit > 0
        ? Math.min(parsedLimit, MAX_SERVICES_LIMIT)
        : DEFAULT_SERVICES_LIMIT;

    const totalCount = await Service.countDocuments(queryFilter);
    const totalPages = Math.max(1, Math.ceil(totalCount / safeLimit));

    const parsedPage = Number.parseInt(page, 10);
    const requestedPage =
      Number.isFinite(parsedPage) && parsedPage > 0 ? parsedPage : 1;
    const currentPage = Math.min(requestedPage, totalPages);
    const skipCount = (currentPage - 1) * safeLimit;

    const rawServices = await Service.find(queryFilter)
      .sort(sortOption)
      .skip(skipCount)
      .limit(safeLimit);

    const withTech = await attachLatestTechnicianNames(rawServices);
    const services = await attachRatingsToServices(withTech);

    res.status(200).json({
      success: true,
      count: services.length,
      totalCount,
      totalPages,
      page: currentPage,
      currentPage,
      limit: safeLimit,
      hasPrevPage: currentPage > 1,
      hasNextPage: currentPage < totalPages,
      data: services,
    });
  } catch (error) {
    console.error("Error fetching services:", error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
});

app.get("/api/services/:id", async (req, res) => {
  try {
    const rawId = String(req.params.id || "").trim();
    let service = null;

    if (/^[0-9a-fA-F]{24}$/.test(rawId)) {
      service = await Service.findById(rawId);
    }

    if (!service) {
      service = await Service.collection.findOne({
        $or: [{ _id: rawId }, { id: rawId }, { slug: rawId }],
      });
    }

    if (!service) {
      return res.status(404).json({
        success: false,
        message: "Service not found",
      });
    }

    let technicianSummary = {
      _id: null,
      name: service.technicianName || "Verified Technician",
      email: service.technicianEmail || "",
      avatar: "",
      area: service.area || "",
      bio: "",
      phone: "",
      plan: "free",
      isVerifiedPro: false,
    };

    const techUser = await findTechnicianUserRecord(service);
    if (techUser) {
      const techPlan = normalizeUserPlan(techUser.plan);
      technicianSummary = {
        _id: techUser._id,
        name: techUser.name || service.technicianName || "Verified Technician",
        email: techUser.email || service.technicianEmail || "",
        avatar: techUser.avatar || "",
        area: techUser.area || service.area || "",
        bio: techUser.bio || "",
        phone: techUser.phone || "",
        plan: techPlan,
        isVerifiedPro: techPlan === "pro",
      };
    }

    const ratingSummary = (await recalculateServiceRating(service._id)) || {
      averageRating: 0,
      reviewCount: 0,
      reviews: [],
    };

    const serviceObj =
      typeof service.toObject === "function"
        ? service.toObject()
        : { ...service };
    serviceObj.technicianName = technicianSummary.name;
    serviceObj.technicianPlan = technicianSummary.plan;
    serviceObj.isVerifiedPro = technicianSummary.isVerifiedPro;
    serviceObj.technician = technicianSummary;
    serviceObj.averageRating = ratingSummary.averageRating;
    serviceObj.reviewCount = ratingSummary.reviewCount;
    serviceObj.reviews = ratingSummary.reviews;

    res.status(200).json({
      success: true,
      data: serviceObj,
      technician: technicianSummary,
      averageRating: ratingSummary.averageRating,
      reviewCount: ratingSummary.reviewCount,
      reviews: ratingSummary.reviews,
    });
  } catch (error) {
    console.error("Error fetching service details:", error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
});

async function startServer() {
  try {
    await connectDB();

    app.listen(port, () => {
      console.log(`FixMate Server is running on port ${port}`);
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();

const DEMO_USER_EMAILS = [
  "arif.customer@fixmate.app",
  "tariq.tech@fixmate.app",
  "nadia.tech@fixmate.app",
  "admin@fixmate.app",
];

app.get("/api/auth/demo-users", async (req, res) => {
  try {
    const dbDemoUsers = await User.find({
      email: { $in: DEMO_USER_EMAILS },
    }).select("name email role avatar");

    const userMap = new Map(
      dbDemoUsers.map((u) => [String(u.email || "").toLowerCase().trim(), u])
    );

    const data = DEMO_USER_EMAILS.map((email) => {
      const found = userMap.get(email);
      return {
        email,
        name: found?.name || "",
        role: found?.role || "",
        avatar: found?.avatar || "",
      };
    });

    res.status(200).json({
      success: true,
      data,
    });
  } catch (error) {
    console.error("Error fetching demo users:", error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
});
