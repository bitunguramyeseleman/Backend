const express = require("express");
const con = require("./db");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

const app = express();

app.use(express.json());
app.use(cors());

const port = process.env.PORT || 4000;

app.post("/login", (req, res) => {
    const { Username, Password } = req.body;

    const sql = "SELECT * FROM Users WHERE Username = ?";

    con.query(sql, [Username], async (err, result) => {
        if (err) return res.status(500).json({ message: "Database error" });

        if (result.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const user = result[0];

        try {
            const match = await bcrypt.compare(Password, user.Password);

            if (!match) {
                return res.status(401).json({ message: "Invalid password" });
            }

            res.status(200).json({
                message: "Login successful",
                user: {
                    UserID: user.UserID,
                    FullName: user.FullName,
                    Username: user.Username,
                    Email: user.Email
                }
            });

        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });
});

app.post("/users", async (req, res) => {
    try {
        const { FullName, Email, Username, Password } = req.body;

        const hashedPassword = await bcrypt.hash(Password, 10);

        const sql = `
            INSERT INTO Users
            (FullName, Email, Username, Password)
            VALUES (?, ?, ?, ?)
        `;

        con.query(sql, [FullName, Email, Username, hashedPassword], (err, result) => {
            if (err) return res.status(500).json(err);

            res.status(201).json({
                message: "User Added Successfully",
                userId: result.insertId
            });
        });

    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});
app.post("/forgot-password", (req, res) => {
    const { Email } = req.body;

    const sql = "SELECT * FROM Users WHERE Email = ?";

    con.query(sql, [Email], (err, result) => {
        if (err) return res.status(500).json({ message: "Database error" });

        if (result.length === 0) {
            return res.status(404).json({ message: "Email not found" });
        }

        const token = crypto.randomBytes(32).toString("hex");

        const expiry = Date.now() + 3600000; // 1 hour

        const updateSql = `
            UPDATE Users 
            SET resetToken = ?, resetTokenExpiry = ?
            WHERE Email = ?
        `;

        con.query(updateSql, [token, expiry, Email], (err2) => {
            if (err2) return res.status(500).json(err2);

            const resetLink = `http://localhost:5173/reset-password/${token}`;

            res.json({
                message: "Reset link generated successfully",
                resetLink
            });
        });
    });
});

app.post("/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    const { Password } = req.body;

    const sql = `
        SELECT * FROM Users 
        WHERE resetToken = ?
    `;

    con.query(sql, [token], async (err, result) => {
        if (err) return res.status(500).json({ message: "Database error" });

        if (result.length === 0) {
            return res.status(400).json({ message: "Invalid token" });
        }

        const user = result[0];

        if (user.resetTokenExpiry < Date.now()) {
            return res.status(400).json({
                message: "Token expired"
            });
        }

        const hashedPassword = await bcrypt.hash(Password, 10);

        const updateSql = `
            UPDATE Users 
            SET Password = ?, resetToken = NULL, resetTokenExpiry = NULL
            WHERE UserID = ?
        `;

        con.query(updateSql, [hashedPassword, user.UserID], (err2) => {
            if (err2) return res.status(500).json(err2);

            res.json({
                message: "Password reset successful"
            });
        });
    });
});
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
