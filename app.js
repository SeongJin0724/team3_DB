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

const sendVerificationEmail = async (email, verificationCode) => {
  const mailOptions = {
    from: process.env.EMAIL_USERNAME,
    to: email,
    subject: "회원가입 인증",
    text: `인증 코드: ${verificationCode}`,
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error("이메일 전송 실패:", error);
  }
};

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

// 회원가입 API
app.post("/api/signup", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);
  const verificationCode = Math.floor(
    100000 + Math.random() * 900000
  ).toString(); // 6자리 인증 코드 생성

  try {
    const conn = await pool.getConnection();
    await conn.query(
      "INSERT INTO user(email, password, verification_code, verification_expires) VALUES (?, ?, ?, ADDDATE(NOW(), INTERVAL 1 DAY))",
      [email, hashedPassword, verificationCode]
    );
    await conn.end();

    sendVerificationEmail(email, verificationCode);

    res.status(200).send("회원가입 성공. 인증 코드가 이메일로 발송되었습니다.");
  } catch (error) {
    res.status(500).send("서버 에러");
  }
});
// 이메일 인증 API
app.post("/api/verify-email", async (req, res) => {
  const { email, verificationCode } = req.body;

  try {
    // 데이터베이스에서 사용자 검색
    const userQuery = "SELECT * FROM user WHERE email = ?";
    const user = await db.query(userQuery, [email]);

    if (user.length > 0) {
      // 인증 코드와 만료 시간 확인
      if (
        user[0].verificationCode === verificationCode &&
        new Date() < new Date(user[0].verificationCodeExpires)
      ) {
        // 사용자의 verified 상태 업데이트
        const updateQuery = "UPDATE users SET verified = 1 WHERE email = ?";
        await db.query(updateQuery, [email]);
        res
          .status(200)
          .json({ message: "이메일 인증이 성공적으로 완료되었습니다." });
      } else {
        res.status(400).json({
          message: "잘못된 인증 코드이거나 인증 코드가 만료되었습니다.",
        });
      }
    } else {
      res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }
  } catch (error) {
    console.error("이메일 인증 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
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
app.get("/api/search", (req, res) => {
  const searchTerm = req.query.term;

  if (!searchTerm) {
    return res.status(400).send({ error: "검색어를 입력해주세요." });
  }
  let query = `SELECT * FROM item 
  WHERE title LIKE '%${searchTerm}%' OR
   category LIKE '%${searchTerm}%' OR
   subCategory LIKE '%${searchTerm}%' OR 
  brand LIKE '%${searchTerm}%'`;

  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
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
