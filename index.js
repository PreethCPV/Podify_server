import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import cors from "cors";
import cookieParser from "cookie-parser";
dotenv.config();
import { UserRouter } from "./routes/user_rt.js";
//const express = require("express");
//.env is used to write url and keys

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true, // or whatever your frontend URL is
  })
);
app.use(cookieParser());
app.use("/auth", UserRouter);

async function dbconnect() {
  await mongoose.connect(
    "mongodb+srv://preethamvenkatram:Preeth0987123@podify1.t5nxief.mongodb.net/",
    {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    }
  );
  console.log("db connection successful");
}
app.listen(process.env.PORT, () => {
  console.log("Server is running in ", process.env.PORT);
  dbconnect();
});
