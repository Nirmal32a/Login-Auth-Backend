import express from "express";
import cors from "cors";
import 'dotenv/config';
import cookieparser from "cookie-parser";

import connectDB from "./config/mongodb.js";
import authRouter from "./routes/authRoutes.js";
import userRouter from "./routes/userRoutes.js";

const app = express();
const port = process.env.PORT || 5000;
connectDB();

app.use(express.json());
app.use(cors());
app.use(cookieparser({credentials: true}));
// API Endpoints
app.get("/", (req, res) => res.send("API Working"));
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});