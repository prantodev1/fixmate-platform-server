# AGENTS.md

Backend REST API for **FixMate**, an on-demand device/appliance repair platform. Express 5 + MongoDB (Mongoose) + JWT/RBAC + optional Stripe. Serves a separate Next.js client.

## Commands

```bash
npm install          # install deps
npm run dev          # nodemon index.js (local dev)
npm start            # node index.js (production)
npm run seed         # node scripts/seed.js — re-seeds demo users/services/bookings
```

- No test runner, linter, or formatter is configured. There is no build step.
- Requires a reachable MongoDB (`MONGODB_URI`) or the server exits on startup.
- `npm run seed` is destructive for the two seeded technicians' services and bookings; users are upserted with `$setOnInsert` (existing passwords are preserved). All seed users get password `FixMate@123`.

## Environment variables

Load from `.env` via `dotenv` in `index.js`, `config/db.js`, and `scripts/seed.js`.

| Variable | Purpose |
| :--- | :--- |
| `PORT` | HTTP port (default `5000`) |
| `MONGODB_URI` | Mongo connection string including credentials (required) |
| `DB_NAME` | Database name (default `fixmateDB`) |
| `DNS_SERVERS` | Comma-separated resolvers applied via `dns.setServers()` before connecting (e.g. `8.8.8.8,1.1.1.1`) |
| `JWT_SECRET` | JWT signing secret (fallback `fixmate_secret_key` — dev only) |
| `CLIENT_URL` | Allowed CORS origin + Stripe redirect base (`http://localhost:3000` is always allowed) |
| `STRIPE_SECRET_KEY` | Enables the Stripe SDK; without it Pro upgrades fall back to direct activation |
| `STRIPE_PRO_PRICE_ID` | Stripe recurring price for the Pro plan; without it checkout uses direct activation |
| `PRO_PLAN_PRICE` | Pro monthly price used in records (default `19`) |
| `NODE_ENV` | Standard runtime flag |

Never commit `.env` (already gitignored). Do not print secrets in logs or responses.

## Architecture

```text
index.js                    # entire API: app setup, middleware, all routes, helpers
config/db.js                # connectDB() → DNS setup, mongoose.connect, retry/exit on failure
models/                     # Mongoose schemas: User, Service, Booking, Payment, ContactMessage
scripts/seed.js             # seed runner
seed/fixmateSeedData.js     # seedUsers / seedServices / seedBookings datasets
```

- **All routes live in `index.js`** (~2,700 lines, no routers/controllers/services split). Add new endpoints there, in the relevant section, and extend the closest helper rather than creating new layers.
- Server bootstrap is `startServer()` near the end of the file; routes registered after that call still work because `app.listen` happens only after `connectDB()` resolves.
- CommonJS only (`require` / `module.exports`), `"type": "commonjs"`.
- Node 18+ is required: `/api/auth/google` uses global `fetch`.
- Reusable handlers are named `*Handler` and mounted on multiple alias routes (e.g. `createTechnicianServiceHandler` on `/api/services` and `/api/technician/services`). Follow that pattern when a feature is exposed under both `/api/...` and legacy `/api/technician/...` paths.
- `connectDB()` applies `DNS_SERVERS` (falling back to `8.8.8.8,1.1.1.1` only if the initial connect fails with a DNS error) because local resolvers on `127.0.0.1` (VPN/AV proxies) often refuse `mongodb+srv` SRV lookups. Diagnose with `dns.getServers()` / `dns.resolveSrv(...)` before suspecting Atlas itself.

### Data-layer notes

- Schema files own validation/enums; business rules live in route handlers.
- `Booking` schema **does not declare** `statusHistory`, `rating`, `review`, `reviewedAt`, or `finalAmount` writes for history — these are stored via `Booking.collection.updateOne` / raw driver queries and exposed through `normalizeBookingRecord()` + `buildStatusHistory()`. Do not assume Mongoose will persist arbitrary extra fields.
- Raw `Model.collection.find(...)` is used when full documents (including undeclared fields) are needed; results pass through the normalizers before being returned.
- Denormalization is intentional: technician/customer `name`/`email`/`avatar` are copied onto `Service`/`Booking`, then refreshed at read time from `User` (`attachLatestTechnicianNames*`, `mapCustomersByBookingRecords`) and on profile update (`PATCH /api/auth/profile`).
- `Service.averageRating`/`reviewCount` are recomputed from reviewed bookings (`recalculateServiceRating`, `attachRatingsToServices`), not written by the client.
- Ownership is checked by **either** id or normalized lowercase email (`technicianId`/`technicianEmail`, `customerId`/`customerEmail`). Keep both paths when adding owner-scoped logic.

## Conventions

- 2-space indent, double quotes, semicolons, trailing commas in multiline literals.
- Every JSON response is shaped `{ success: boolean, message?: string, data?: ..., ...metadata }`; errors use `success: false` with a human-readable `message` and an appropriate 4xx/5xx status. Mutations also return counts/plans alongside `data` when useful.
- Handlers are `async` and wrap logic in `try/catch`; generic failures log `console.error("<context>:", error)` and return `500 { success: false, message: "Internal Server Error" }`.
- Validate required input at the top of each handler and return `400` before touching the DB. Normalize emails with `String(x).toLowerCase().trim()`.
- Auth flow: `verifyToken` (Bearer JWT, 7-day expiry) → `verifyCustomer` / `verifyTechnician` / `verifyAdmin`. Roles are compared lowercase; JWT payload is `{ userId, email, role }`.
- Public service listings expose only `status`/`approvalStatus` in `approved|active|published` (or unset) and available records. Do not leak `pending`/`rejected` services through public endpoints.
- Passwords are hashed with `bcryptjs` (10 rounds) only on signup; never return the `password` field — use `formatSafeUser()`.
- Use `escapeRegex()` before building `$regex` from user input.

## Domain rules and state machines

- **Booking status:** `requested → accepted → in-progress → completed`; terminal `cancelled` (customer, only from `requested`) and `rejected` (technician, from `requested`). Technicians may only advance along `allowedTransitions` in `PATCH /api/bookings/:id/status`.
- **Payment:** only the owning customer, only when `status === "completed"` and `paymentStatus !== "paid"`. Marks booking paid and writes a `Payment` record (`type: "booking"`). Both `/api/payments/create-checkout-session` and `/api/bookings/:id/pay` currently settle directly (no real Stripe Checkout for bookings).
- **Review:** owner only, requires `paymentStatus === "paid"`, rating 1–5 and non-empty text; updates the booking and recalculates the service rating. Available at `/api/bookings/:id/review` and `PATCH /api/bookings/:id`.
- **Booking creation:** requires phone, address, future-or-today `preferredDate`, and a problem description of at least 20 characters; blocks duplicate active bookings for the same service + customer email.
- **Service plans:** free technicians are limited to 3 services (`FREE_PLAN_SERVICE_LIMIT`); Pro is unlimited plus a Verified Pro badge. Editing core fields of an `approved` service resets it to `pending`.
- **Pro upgrades:** `/api/subscriptions/pro/checkout-session` creates a Stripe subscription session when Stripe is configured, otherwise activates directly; `/confirm` reconciles the Stripe session. Activation is idempotent per `stripeSessionId`.
- **Contact:** public `POST /api/contact`; requires name, valid phone (7–15 digits, optional `+`), and a 15+ character message. Admin manages status (`unread`/`read`/`replied`) and deletion.

## Route map

| Area | Endpoints |
| :--- | :--- |
| Health | `GET /` (HTML status page) |
| Auth | `POST /api/auth/signup`, `/login`, `/google`, `GET /api/auth/me`, `GET /api/auth/demo-users` |
| Profile | `PATCH /api/users/profile`, `PATCH /api/auth/profile` |
| Subscriptions | `GET /api/subscriptions/pro/status`, `POST .../checkout-session`, `POST .../confirm` |
| Services | `GET /api/services` (paginated/search/sort/filter, max 50), `GET /api/services/:id` (id/slug), `POST/PATCH/DELETE /api/services[/:id]` (technician), plus `/api/technician/services` aliases |
| Bookings | `POST /api/bookings`, `GET /api/bookings/my`, `PATCH /api/bookings/:id/cancel`, `PATCH /api/bookings/:id/status`, `GET /api/bookings/technician` / `/api/technician/bookings` |
| Payments | `POST /api/payments/create-checkout-session`, `POST /api/bookings/:id/pay` |
| Reviews | `POST /api/bookings/:id/review`, `PATCH /api/bookings/:id`, `GET /api/reviews` |
| Admin | `GET /api/admin/users`, `PATCH /api/admin/users/:id/role`, `GET /api/admin/services`, `PATCH /api/admin/services/:id/{approval,status}`, `GET /api/admin/bookings`, `GET /api/admin/payments`, `GET /api/admin/messages`, `PATCH/DELETE /api/admin/messages/:id[/status]` |

Demo accounts (constant `DEMO_USER_EMAILS`): `arif.customer@fixmate.app`, `tariq.tech@fixmate.app`, `nadia.tech@fixmate.app`, `admin@fixmate.app`.
