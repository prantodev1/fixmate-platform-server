const dns = require("dns");
const mongoose = require("mongoose");
require("dotenv").config();

const FALLBACK_DNS_SERVERS = ["8.8.8.8", "1.1.1.1"];

function applyDnsServers(servers = []) {
  const validServers = servers.filter(Boolean);
  if (validServers.length === 0) return false;

  try {
    dns.setServers(validServers);
    return true;
  } catch (error) {
    console.warn("Could not apply custom DNS servers:", error.message);
    return false;
  }
}

function configureDnsResolver() {
  const configuredServers = String(process.env.DNS_SERVERS || "")
    .split(",")
    .map((server) => server.trim())
    .filter(Boolean);

  if (configuredServers.length > 0 && applyDnsServers(configuredServers)) {
    console.log(`Using DNS servers: ${configuredServers.join(", ")}`);
  }

  // Prefer IPv4 for Atlas SRV/host lookups when both stacks are available.
  if (typeof dns.setDefaultResultOrder === "function") {
    dns.setDefaultResultOrder("ipv4first");
  }
}

function isDnsResolutionError(error) {
  return (
    error?.syscall === "querySrv" ||
    ["ECONNREFUSED", "ESERVFAIL", "ETIMEOUT", "ENOTFOUND", "EREFUSED"].includes(
      error?.code
    )
  );
}

const connectDB = async () => {
  const mongoUri = process.env.MONGODB_URI;

  if (!mongoUri) {
    console.error("MongoDB connection error: MONGODB_URI is not set");
    process.exit(1);
  }

  configureDnsResolver();

  const connectOptions = {
    dbName: process.env.DB_NAME || "fixmateDB",
  };

  try {
    await mongoose.connect(mongoUri, connectOptions);
    console.log("Connected to MongoDB via Mongoose successfully!");
  } catch (error) {
    // Some local resolvers (VPN/antivirus proxies on 127.0.0.1) refuse SRV
    // queries. Retry once with public DNS before giving up.
    if (isDnsResolutionError(error) && applyDnsServers(FALLBACK_DNS_SERVERS)) {
      try {
        await mongoose.connect(mongoUri, connectOptions);
        console.log(
          `Connected to MongoDB via Mongoose successfully (fallback DNS: ${FALLBACK_DNS_SERVERS.join(", ")})!`
        );
        return;
      } catch (retryError) {
        console.error("MongoDB connection error:", retryError);
        process.exit(1);
      }
    }

    console.error("MongoDB connection error:", error);
    process.exit(1);
  }
};

module.exports = { connectDB };
