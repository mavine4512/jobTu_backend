const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");

const saltRounds = 10;
const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
    methods: "GET,POST",
  })
);
app.use(cookieParser());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "EMS",
});

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ error: "You are not authenticated" });
  } else {
    jwt.verify(token, "jwt-secret-keys", (err, decoded) => {
      if (err) {
        return res.json({ error: "Invalid token" });
      } else {
        req.username = decoded.username;
        next();
      }
    });
  }
};

app.get("/", verifyUser, (req, res) => {
  return res.json({ status: "success", username: req.username });
});

// app.post("/register", (req, res) => {
//   const sql =
//     "INSERT INTO login (`firstName`,`lastName`,`email`, `password`) VALUES (?, ?, ?, ?)";

//   bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
//     if (err) return res.json({ error: "Error for hashing password" });

//     const values = [
//       req.body.firstName,
//       req.body.lastName,
//       req.body.email,
//       hash,
//     ];

//     db.query(sql, [values], (err, result) => {
//       if (err)
//         return res.json({
//           Error: "Inserting data Error in server",
//           Details: err,
//         });

//       return res.json({ status: "success" });
//     });
//   });
// });

app.post("/register", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);

    const sql =
      "INSERT INTO login (`firstName`,`lastName`,`email`, `password`) VALUES (?, ?, ?, ?)";

    const values = [
      req.body.firstName,
      req.body.lastName,
      req.body.email,
      hashedPassword,
    ];

    db.query(sql, values, (err, result) => {
      if (err) {
        console.error("Error inserting data:", err);
        return res.json({ error: "Error inserting data in the server" });
      }

      return res.json({ status: "success" });
    });
  } catch (error) {
    console.error("Error:", error);
    return res.json({ error: "An unexpected error occurred" });
  }
});

app.post("/login", (req, res) => {
  const sql = "SELECT * FROM login WHERE email =?";
  db.query(sql, [req.body.email], (err, result) => {
    if (err) return res.json({ error: "Login Error in server" });
    if (result.length > 0) {
      bcrypt.compare(
        req.body.password.toString(),
        result[0].password,
        (err, response) => {
          if (err) return res.json({ error: "Password compare error" });
          if (response) {
            const username = result[0].firstName + " " + result[0].lastName;
            const token = jwt.sign({ username }, "jwt-secret-keys", {
              expiresIn: "1d",
            });
            res.cookie("token", token);
            return res.json({ status: "success" });
          } else {
            return res.json({ error: "Password not matched" });
          }
        }
      );
    } else {
      return res.json({ error: "Email not found" });
    }
  });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ status: "success" });
});

app.listen(3001, () => {
  console.log("Server is running on port 3001");
});
