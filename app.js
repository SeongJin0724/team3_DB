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
// const sendVerificationEmail = (email, verificationCode) => {
//   const mailOptions = {
//     from: process.env.EMAIL_USERNAME,
//     to: email,
//     subject: "이메일 인증 코드",
//     text: `인증 코드: ${verificationCode}`,
//   };

//   transporter.sendMail(mailOptions, function (error, info) {
//     if (error) {
//       console.log(error);
//     } else {
//       console.log("Email sent: " + info.response);
//     }
//   });
// };
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

app.post("/send-verification-code", async (req, res) => {
  const { email } = req.body;
  const verificationCode = Math.floor(1000 + Math.random() * 9000); // 4자리 숫자 코드 생성
  const codeExpires = Math.floor((new Date().getTime() + 3 * 60 * 1000) / 1000); // 밀리초 대신 초 단위로

  await db.query(
    `INSERT INTO user (email, verification_code, code_expires_at) VALUES (?, ?, ?)`,
    [email, verificationCode, codeExpires]
  );

  // 이메일 전송 로직
  await transporter.sendMail({
    from: process.env.EMAIL_USERNAME,
    to: email,
    subject: "이메일 인증 코드",
    text: `이메일 인증코드: ${verificationCode}`,
  });

  res.send("Verification code sent.");
});

//이메일 코드 검증
app.post("/verify-code", async (req, res) => {
  const { email, verificationCode } = req.body;
  // 사용자의 이메일과 인증 코드로 검증
  const user = await db.query(
    `SELECT user_id FROM user WHERE email = ? AND verification_code = ? AND code_expires_at > ?`,
    [email, verificationCode, new Date().getTime()]
  );

  if (user.length === 0) {
    return res.status(400).send("Invalid or expired verification code.");
  }

  // 이메일이 검증된 것으로 표시 (예: 이메일 인증 상태 업데이트)
  // 실제 구현에서는 이메일 인증 상태를 나타내는 별도의 필드가 필요할 수 있습니다.
  await db.query(`UPDATE user SET email_verified = TRUE WHERE user_id = ?`, [
    user[0].user_id,
  ]);

  res.send("Email verified successfully.");
});

const saltRounds = 10; // 비밀번호 해싱에 사용될 salt의 라운드 수

app.post("/register", async (req, res) => {
  const { email, password, name, tel, address } = req.body;

  // 먼저 사용자의 email로 user_id를 찾습니다.
  const user = await db.query(`SELECT user_id FROM user WHERE email = ?`, [
    email,
  ]);
  if (user.length === 0) {
    return res.status(404).send("사용자를 찾을 수 없습니다.");
  }
  const userId = user[0].user_id;

  // 비밀번호를 해싱합니다.
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  // user_id를 사용하여 사용자의 나머지 정보를 업데이트합니다.
  await db.query(
    `UPDATE user SET password = ?, name = ?, tel = ?, address = ? WHERE user_id = ?`,
    [hashedPassword, name, tel, address, userId]
  );

  res.send("회원가입이 완료되었습니다.");
});

// app.post("/register", async (req, res) => {
//   const { email, password, name, tel, address } = req.body;
//   const verificationCode = Math.floor(1000 + Math.random() * 900000);
//   const codeExpires = new Date();
//   codeExpires.setMinutes(codeExpires.getMinutes() + 3);

//   try {
//     const conn = await db.getConnection();
//     await conn.query(
//       "INSERT INTO user (email, password, name, tel, address, verification_code, code_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
//       [email, password, name, tel, address, verificationCode, codeExpires]
//     );
//     conn.end();

//     sendVerificationEmail(email, verificationCode); // 이메일 전송 함수 호출

//     res.json({
//       message: "회원가입을 위한 인증 코드가 이메일로 전송되었습니다.",
//     });
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// });
// app.post("/verify-email", async (req, res) => {
//   const { email, verificationCode } = req.body;

//   try {
//     const conn = await db.getConnection();
//     const result = await conn.query(
//       "SELECT * FROM user WHERE email = ? AND verification_code = ? AND code_expires_at > NOW()",
//       [email, verificationCode]
//     );

//     if (result.length > 0) {
//       // 이메일 인증 성공 처리 (예: verified 필드를 1로 업데이트)
//       await conn.query("UPDATE user SET verified = 1 WHERE email = ?", [email]);
//       res.json({ message: "이메일 인증에 성공하였습니다." });
//     } else {
//       res
//         .status(400)
//         .json({ message: "유효하지 않은 인증 코드이거나 만료되었습니다." });
//     }

//     conn.end();
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// });
// // 이메일 인증 코드 보내기 API
// app.post("/api/send-verification-code", (req, res) => {
//   const { email } = req.body;
//   const verificationCode = Math.floor(1000 + Math.random() * 900000); // 6자리 코드 생성
//   const expires = new Date();
//   expires.setMinutes(expires.getMinutes() + 3); // 코드 만료 시간 설정 (10분 후)

//   const mailOptions = {
//     from: process.env.EMAIL_USER,
//     to: email,
//     subject: "회원가입 인증 코드",
//     html: `<p>귀하의 인증 코드는 ${verificationCode}입니다.</p>`,
//   };

//   transporter.sendMail(mailOptions, (error, info) => {
//     if (error) {
//       return res.status(500).send("Error sending email");
//     }

//     // 데이터베이스에 인증 코드 저장
//     const query =
//       "UPDATE user SET verification_code=?, code_expires_at=? WHERE email=?";
//     db.query(query, [verificationCode, expires, email], (error, results) => {
//       if (error) {
//         return res.status(500).send("Error updating database");
//       }
//       res.status(200).send("Verification code sent");
//     });
//   });
// });

// // 이메일 인증 코드 확인 API
// app.post("/api/verify", (req, res) => {
//   const { email, verificationCode } = req.body;

//   const query =
//     "SELECT * FROM user WHERE email=? AND verification_code=? AND code_expires_at > NOW()";
//   db.query(query, [email, verificationCode], (error, results) => {
//     if (error || results.length === 0) {
//       return res.status(400).send("Invalid or expired code");
//     }

//     const updateQuery =
//       "UPDATE user SET verified=1, verification_code=NULL, code_expires_at=NULL WHERE email=?";
//     db.query(updateQuery, [email], (error, results) => {
//       if (error) {
//         return res.status(500).send("Server error");
//       }
//       res.status(200).send("Account verified successfully");
//     });
//   });
// });

// // 회원가입 API
// app.post("/api/signup", (req, res) => {
//   const {
//     email,
//     password,
//     name,
//     tel,
//     address,
//     bankName,
//     accountNum,
//     accountOwner,
//   } = req.body;

//   // 먼저 사용자가 이메일을 인증했는지 확인
//   const verifiedQuery = "SELECT verified FROM user WHERE email = ?";
//   db.query(verifiedQuery, [email], (error, results) => {
//     if (error) {
//       return res.status(500).send("Server error");
//     }
//     if (results.length === 0 || results[0].verified === 0) {
//       return res.status(400).send("Email not verified");
//     }

//     // 사용자 정보를 데이터베이스에 저장하는 쿼리
//     const query =
//       "INSERT INTO user (email, password, name, tel, address, bankName, accountNum, accountOwner, verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)";

//     db.query(
//       query,
//       [email, password, name, tel, address, bankName, accountNum, accountOwner],
//       (error, results) => {
//         if (error) {
//           return res.status(500).send("Server error");
//         }
//         res.status(200).send("User registered successfully.");
//       }
//     );
//   });
// });

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
    console.error("Error:", err);
    res.status(500).send({ error: "서버 에러" });
  }
});

// 신규 판매 상품
app.get("/api/newin", async (req, res) => {
  let limit = 5;
  let offset = parseInt(req.query.offset) || 0;
  try {
    const data = await db.query(
      "SELECT * FROM item ORDER BY releaseDate DESC LIMIT ?, ?",
      [offset, limit]
    );
    res.json(data);
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send({ error: "서버 에러" });
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
