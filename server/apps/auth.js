import { Router } from "express";
import { db } from "../utils/db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken"

const authRouter = Router();

// 🐨 Todo: Exercise #1
// ให้สร้าง API เพื่อเอาไว้ Register ตัว User แล้วเก็บข้อมูลไว้ใน Database ตามตารางที่ออกแบบไว้
authRouter.post("/register", async (req, res) => {
    const user = {
        username: req.body.username,
        password: req.body.password,
        firstName: req.body.firstName,
        lastName: req.body.lastName
    }
    const salt = await bcrypt.genSalt(10);
    // now we set user password to hashed password
    user.password = await bcrypt.hash(user.password, salt);

    const collection = db.collection("users");
    await collection.insertOne(user)

    return res.json({
        message: "User has been created successfully"
    })
})


// 🐨 Todo: Exercise #3
// ให้สร้าง API เพื่อเอาไว้ Login ตัว User ตามตารางที่ออกแบบไว้
authRouter.post("/login", async (req, res) => {
    const loginData = {
        username: req.body.username,
        password: req.body.password
    }
    try {
        const collection = db.collection("users");
        const user = await collection.findOne({ username: loginData.username });
        
        // ถ้าไม่เจอ user
        if (!user) {
            return res.status(401).json({
                message: "Invalid username or password"
            });
        }
        
        // ตรวจสอบ password
        const isPasswordValid = await bcrypt.compare(loginData.password, user.password);
        
        if (isPasswordValid) {
            const token = jwt.sign(
                {
                  id: user._id, // ใช้ _id แทน id
                  firstName: user.firstName,
                  lastName: user.lastName
                },
                process.env.SECRET_KEY,
                {
                  expiresIn: '900000',
                }
            );
            
            return res.json({
                message: "Login successful",
                token: token
            });
        } else {
            // Password ไม่ถูกต้อง
            return res.status(401).json({
                message: "Invalid username or password"
            });
        }
        
    } catch (error) {
        console.error("Login error:", error);
        return res.status(500).json({
            message: "Internal server error"
        });
    }
})


export default authRouter;
