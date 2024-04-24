require("dotenv").config();
var createError = require("http-errors");
var express = require("express");
var path = require("path");
const cors = require("cors");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
const nodemailer = require("nodemailer");
const nunjucks = require("nunjucks");
const bcrypt = require("bcrypt");
const PORT = process.env.PORT || 4000;
var indexRouter = require("./routes/index");
// var usersRouter = require('./routes/users');

var app = express();
const mysql = require("mysql2/promise");

const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD,
  },
});

app.use(cors());
// view engine setup
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "njk");
nunjucks.configure("views", {
  express: app,
  watch: true,
});

app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.use("/", indexRouter);
// app.use('/users', usersRouter);

// 인증 코드 발송 API
app.post("/api/send-verification-code", async (req, res) => {
  const { email } = req.body;
  const verificationCode = Math.floor(1000 + Math.random() * 9000).toString(); // 4자리 인증 코드 생성
  const codeExpires = new Date();
  codeExpires.setMinutes(codeExpires.getMinutes() + 3); // 3분 후 만료

  try {
    // 인증 코드와 만료 시간을 임시 저장소에 저장하는 로직을 추가할 수 있음
    // 예: Redis, Memcached 등을 사용하여 email을 키로 하여 verificationCode와 codeExpires를 저장
    // 여기서는 데이터베이스 사용 로직을 제거합니다.

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "회원가입 인증 코드",
      html: `<p>귀하의 인증 코드는 ${verificationCode}입니다.</p>`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res.status(500).send("Email send error");
      }
      res.status(200).send("Verification code sent");
    });
  } catch (error) {
    console.error("Error sending email code:", error);
    res.status(500).send("Failed to send email code");
  }
});

// 인증 코드 확인 API
app.post("/api/verify", (req, res) => {
  const { email, verificationCode } = req.body;
  const query =
    "SELECT * FROM user WHERE email = ? AND verification_code = ? AND code_expires_at > NOW()";

  db.query(query, [email, verificationCode], (error, results) => {
    if (error || results.length === 0) {
      return res.status(400).send("Invalid or expired code");
    }

    // 인증 성공시 verified 상태를 1로 업데이트
    const updateQuery = "UPDATE user SET verified = 1 WHERE email = ?";
    db.query(updateQuery, [email], (error, results) => {
      if (error) {
        return res.status(500).send("Server error");
      }
      res.status(200).send("Account verified successfully.");
    });
  });
});

// 회원가입 API
app.post("/api/signup", (req, res) => {
  const {
    email,
    password,
    name,
    tel,
    address,
    bankName,
    accountNum,
    accountOwner,
  } = req.body;

  // 먼저 사용자가 이메일을 인증했는지 확인
  const verifiedQuery = "SELECT verified FROM user WHERE email = ?";
  db.query(verifiedQuery, [email], (error, results) => {
    if (error) {
      return res.status(500).send("Server error");
    }
    if (results.length === 0 || results[0].verified === 0) {
      return res.status(400).send("Email not verified");
    }

    // 사용자 정보를 데이터베이스에 저장하는 쿼리
    const query =
      "INSERT INTO user (email, password, name, tel, address, bankName, accountNum, accountOwner, verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)";

    db.query(
      query,
      [email, password, name, tel, address, bankName, accountNum, accountOwner],
      (error, results) => {
        if (error) {
          return res.status(500).send("Server error");
        }
        res.status(200).send("User registered successfully.");
      }
    );
  });
});

// 로그인 API (Promise 기반으로 수정)
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM user WHERE email = ?";
  try {
    const [users, _] = await db.query(sql, [email]); // 배열 구조 분해를 사용하여 첫 번째 원소(결과)를 가져옴

    if (users.length > 0) {
      const comparison = await bcrypt.compare(password, users[0].password);
      if (comparison) {
        res.send({ message: "Logged in successfully!" });
      } else {
        res.status(401).send({ message: "Invalid email or password" });
      }
    } else {
      res.status(401).send({ message: "Invalid email or password" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "An error occurred" });
  }
});

// 유저 조회
app.get("/api/users", async (req, res) => {
  try {
    const [data, fields] = await db.query("SELECT * FROM user");
    res.send(data);
  } catch (err) {
    console.log(err);
    res.status(500).send({ message: "An error occurred" });
  }
});

// 검색
app.get("/api/search", async (req, res) => {
  const searchTerm = req.query.term;

  if (!searchTerm) {
    return res.status(400).send({ error: "검색어를 입력해주세요." });
  }

  let query = `SELECT * FROM item 
  WHERE title LIKE ? OR
  category LIKE ? OR
  subCategory LIKE ? OR 
  brand LIKE ?`;
  const likeSearchTerm = `%${searchTerm}%`;

  try {
    const [data] = await db.query(query, [
      likeSearchTerm,
      likeSearchTerm,
      likeSearchTerm,
      likeSearchTerm,
    ]);
    res.json(data);
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send({ error: "서버 에러" });
  }
});

// 브랜드
app.get("/api/brands/:brand", async (req, res) => {
  const brand = req.params.brand;

  try {
    const results = await db.query("SELECT * FROM item WHERE brand = ?", [
      brand,
    ]);
    res.json(results);
  } catch (err) {
    console.error("데이터베이스 쿼리 중 오류 발생:", err);
    res.status(500).json({ message: "서버 내부 오류가 발생했습니다." });
  }
});

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get("env") === "development" ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render("error");
});
app.listen(PORT, () => {
  console.log(`Server On : http://localhost:${PORT}`);
});
module.exports = app;
