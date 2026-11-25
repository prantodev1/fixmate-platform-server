const mongoose = require("mongoose");

const paymentSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: ["booking", "subscription"],
      default: "booking",
    },
    plan: {
      type: String,
      enum: ["free", "pro", ""],
      default: "",
    },
    bookingId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Booking",
      default: null,
    },
    serviceTitle: {
      type: String,
      default: "",
      trim: true,
    },
    customerName: {
      type: String,
      default: "",
      trim: true,
    },
    customerEmail: {
      type: String,
      default: "",
      lowercase: true,
      trim: true,
    },
    technicianId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    technicianName: {
      type: String,
      default: "",
      trim: true,
    },
    technicianEmail: {
      type: String,
      default: "",
      lowercase: true,
      trim: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    userName: {
      type: String,
      required: true,
      trim: true,
    },
    userEmail: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },
    userRole: {
      type: String,
      enum: ["customer", "technician", "admin"],
      default: "customer",
    },
    amount: {
      type: Number,
      required: true,
      min: 0,
    },
    currency: {
      type: String,
      default: "usd",
      lowercase: true,
      trim: true,
    },
    provider: {
      type: String,
      default: "stripe",
      trim: true,
    },
    transactionId: {
      type: String,
      required: true,
      trim: true,
    },
    stripeSessionId: {
      type: String,
      default: undefined,
      trim: true,
    },
    stripeSubscriptionId: {
      type: String,
      default: "",
      trim: true,
    },
    status: {
      type: String,
      enum: ["paid", "pending", "failed", "refunded"],
      default: "paid",
    },
    paidAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

paymentSchema.index({ userId: 1, createdAt: -1 });
paymentSchema.index({ type: 1, status: 1, paidAt: -1 });
paymentSchema.index({ transactionId: 1 });
paymentSchema.index({ bookingId: 1, type: 1 });
paymentSchema.index(
  { stripeSessionId: 1 },
  { unique: true, sparse: true }
);

module.exports = mongoose.model("Payment", paymentSchema);