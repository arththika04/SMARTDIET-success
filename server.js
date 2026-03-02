import express from "express";
import dotenv from "dotenv";
dotenv.config();
import cors from "cors";
import helmet from "helmet";
import passport from "passport";
import session from "express-session";
import cookieParser from "cookie-parser";

import "./config/passport.js";
import connectDB from "./config/db.js";
import authRoutes from "./routes/authRoutes.js";

connectDB();

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: "http://localhost:3000",  // later env-la vachu maathanum
    credentials: true,
  })
);

app.use(helmet());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "smartdiet-secret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use("/api/auth", authRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
