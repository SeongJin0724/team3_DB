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
const crypto = require("crypto");
const secret = crypto.randomBytes(64).toString("hex");
const jwt = require("jsonwebtoken");
const multer = require("multer");

// var indexRouter = require("./routes/index");
console.log(secret);
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
app.use(cors({ origin: true, credentials: true }));

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

// app.use("/", indexRouter);
// app.use('/users', usersRouter);

// 사용자 인증 미들웨어 예시
async function authenticateToken(req, res, next) {
  // 요청 헤더에서 토큰 추출
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  console.log(token);
  if (token == null) {
    return res.sendStatus(401); // 인증되지 않음
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log(decoded);
    req.user = decoded; // 수정된 부분: 토큰에서 추출한 사용자 ID를 req.user 객체에 추가
    next(); // 다음 미들웨어로 이동
  } catch (err) {
    return res.sendStatus(403); // 유효하지 않은 토큰
  }
}

app.post("/send-verification-code", async (req, res) => {
  const { email } = req.body;
  const verificationCode = Math.floor(1000 + Math.random() * 9000); // 4자리 숫자 코드 생성
  const codeExpires = new Date(new Date().getTime() + 3 * 60 * 1000)
    .toISOString()
    .slice(0, 19)
    .replace("T", " ");
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
  // 현재 시각을 MySQL DATETIME 형식으로 변환
  const now = new Date().toISOString().slice(0, 19).replace("T", " ");

  // 사용자의 이메일과 인증 코드로 검증, 만료되지 않은 코드인지 확인
  const [user] = await db.query(
    `SELECT user_id FROM user WHERE email = ? AND verification_code = ? AND code_expires_at > ?`,
    [email, verificationCode, now]
  );

  if (user.length === 0) {
    return res.status(400).send("Invalid or expired verification code.");
  }

  // 이메일이 검증된 것으로 표시 (예: 이메일 인증 상태 업데이트)
  await db.query(`UPDATE user SET email_verified = TRUE WHERE user_id = ?`, [
    user[0].user_id,
  ]);

  res.send("Email verified successfully.");
});

const saltRounds = 10; // 비밀번호 해싱에 사용될 salt의 라운드 수

app.post("/register", async (req, res) => {
  const { email, password, name, tel, address } = req.body;

  // 먼저 사용자의 이메일로 이메일 인증 여부를 확인합니다.
  const [user] = await db.query(
    `SELECT user_id, email_verified FROM user WHERE email = ?`,
    [email]
  );

  // 사용자가 데이터베이스에 없거나 이메일 인증이 안된 경우
  if (user.length === 0) {
    return res
      .status(404)
      .send("사용자를 찾을 수 없거나 이메일 인증이 필요합니다.");
  }
  if (!user[0].email_verified) {
    return res.status(401).send("이메일 인증이 필요합니다.");
  }

  const userId = user[0].user_id;

  // 비밀번호를 해싱합니다.
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  // 이메일 인증이 된 경우, 나머지 정보를 업데이트합니다.
  await db.query(
    `UPDATE user SET password = ?, name = ?, tel = ?, address = ? WHERE user_id = ? AND email_verified = 1`,
    [hashedPassword, name, tel, address, userId]
  );

  res.send("회원가입이 완료되었습니다.");
});

//로그인
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM user WHERE email = ?";
  try {
    const [users, _] = await db.query(sql, [email]);

    if (users.length > 0) {
      const comparison = await bcrypt.compare(password, users[0].password);
      if (comparison) {
        // JWT 생성 시, 민감한 정보를 제외한 사용자 정보를 포함
        const { password, verification_code, code_expires_at, ...userInfo } =
          users[0];
        const token = jwt.sign({ userData: userInfo }, process.env.JWT_SECRET, {
          expiresIn: "4h",
        });
        // 이렇게 하면 password, verification_code, code_expires_at를 제외한 나머지 사용자 정보가 토큰에 포함됩니다.

        res.cookie("token", token, {
          httpOnly: true,
          sameSite: "strict",
          secure: true,
          maxAge: 4 * 60 * 60 * 1000,
        });

        res.send({
          message: "Logged in successfully!",
          token,
        });
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

// 로그아웃
app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.send({ message: "Logged out successfully!" });
});

// 유저 조회
app.get("/api/user", authenticateToken, async (req, res) => {
  try {
    // 예시로, req.user.id를 사용해 데이터베이스에서 유저 정보를 조회합니다.
    // 실제 구현에서는 데이터베이스 쿼리 방식에 맞게 코드를 수정해야 합니다.
    const userId = req.user.user_id;
    const sql = "SELECT * FROM user WHERE user_id = ?";
    const user = await db.query(sql, [userId]);

    if (user) {
      res.json({ user });
    } else {
      res.status(404).send({ message: "User not found" });
    }
  } catch (err) {
    console.error(err);
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

// 로그인정보
app.put("/api/infochange/:user_id", async (req, res) => {
  const { email, password, tel } = req.body;
  const { user_id } = req.params;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  const sqlUpdate =
    "UPDATE user SET email = ?, password = ?, tel = ? WHERE user_id = ?";
  db.query(sqlUpdate, [email, hashedPassword, tel, user_id], (err, result) => {
    if (err) throw err;
    res.send(result);
  });
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

// 상품 상세페이지
app.get("/api/items/:itemKey", async (req, res) => {
  try {
    const rows = await db.query("SELECT * FROM item WHERE itemKey = ?", [
      req.params.itemKey,
    ]);
    if (rows.length > 0) {
      res.json(rows[0]);
    } else {
      res.status(404).send("상품을 찾을 수 없습니다.");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("서버 에러");
  }
});

// 상품 상세페이지 - 판매/구매 거래리스트
app.get("/api/items/:itemKey/offers", async (req, res) => {
  try {
    const salesRows = await db.query(
      "SELECT * FROM offerDeal WHERE itemKey = ? AND sign = TRUE AND deal = '판매'",
      [req.params.itemKey]
    );
    const purchaseRows = await db.query(
      "SELECT * FROM offerDeal WHERE itemKey = ? AND sign = TRUE AND deal = '구매'",
      [req.params.itemKey]
    );
    if (salesRows.length > 0 || purchaseRows.length > 0) {
      res.json({ sales: salesRows[0], purchases: purchaseRows[0] });
    } else {
      res.status(404).send("상품을 찾을 수 없습니다.");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});

// 스타일
app.get("/api/reviews", async (req, res) => {
  try {
    const data = await db.query("SELECT * FROM reviews");
    res.json(data);
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send({ error: "서버 에러" });
  }
});

// 주소록
app.post("/api/mypage/address", async (req, res) => {
  // 'req.body'에서 'address'와 'user_id' 추출
  const { address, user_id } = req.body;

  try {
    // 'user_id'를 이용하여 해당 사용자의 'address' 정보 업데이트
    const data = await db.query(
      `UPDATE user SET address = ? WHERE user_id = ?`,
      [address, user_id] // 쿼리에 'address'와 'user_id' 사용
    );
    // 업데이트 성공 메시지 전송
    res.json({ message: "주소가 성공적으로 업데이트되었습니다.", data });
  } catch (err) {
    console.error("Error:", err);
    // 서버 에러 응답
    res.status(500).send({ error: "서버 에러" });
  }
});

// accout
let accountInfo = {};

app.post("/api/mypage/account", (req, res) => {
  const { user_id, bankName, accountNum, accountOwner } = req.body;
  // 계좌 정보 업데이트
  (accountInfo[user_id] = bankName), accountNum, accountOwner;
  res.status(200).send({
    message: "계좌 정보가 등록되었습니다.",
    accountInfo: accountInfo[user_id],
  });
});

app.get("/api/mypage/account/:userId", (req, res) => {
  const user_id = req.params.userId;
  const userInfo = accountInfo[user_id];
  if (userInfo) {
    res.status(200).send({ user_id, ...userInfo });
  } else {
    res.status(404).send({ message: "계좌 정보를 찾을 수 없습니다." });
  }
});

// 스타일 업로드
// Multer 설정
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage: storage });

app.use("/uploads", express.static("uploads"));

app.post("/upload-image", upload.single("image"), (req, res) => {
  const imagePath = req.file.path;
  const reviewContent = req.body.review;
  const query = "INSERT INTO reviews (content, img) VALUES (?, ?)";

  db.query(query, [reviewContent, imagePath], (err, results) => {
    if (err) {
      console.error("An error occurred:", err);
      return res.status(500).send("An error occurred.");
    }
    res.send("Review Uploaded Successfully.");
  });
});

//주문
app.get("/api/offerDeal/:dealKey", async (req, res) => {
  try {
    const dealKey = req.params.dealKey;
    const query = `
      SELECT od.dealKey, od.itemKey, od.user_id, od.price, od.fee, 
      od.totalPrice, od.size, it.title, it.brand, it.img 
      FROM offerDeal AS od
      INNER JOIN item AS it ON od.itemKey = it.itemKey 
      WHERE od.dealKey = ?
    `;
    const response = await db.query(query, [dealKey]);
    if (response.length === 0) {
      return res.status(404).send("OfferDeal or Item not found");
    }

    res.json(response[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});

//결제
const axios = require("axios");
const SECRET_KEY = "DEVA4D244E550D373216ADECD766358F6503373E";

app.post("/api/payment/kakao", async (req, res) => {
  const {
    partner_order_id,
    partner_user_id,
    item_name,
    // item_code,
    quantity,
    total_amount,
    tax_free_amount,
  } = req.body;

  try {
    const response = await axios.post(
      "https://open-api.kakaopay.com/online/v1/payment/ready",
      {
        cid: "TC0ONETIME",
        partner_order_id,
        partner_user_id,
        item_name,
        quantity,
        total_amount,
        tax_free_amount,
        approval_url: `http://127.0.0.1:3000/api/payment/approval?dealKey=${partner_order_id}`,
        fail_url: "http://127.0.0.1:3000",
        cancel_url: "http://127.0.0.1:3000",
      },
      {
        headers: {
          Authorization: `SECRET_KEY ${SECRET_KEY}`,
          "Content-type": "application/json",
        },
      }
    );

    // await db.query(
    //   "INSERT INTO `order` (user_id, itemKey, dealKey, price, tid, orderStatus) VALUES (?, ?, ?, ?, ?, ?)",
    //   [
    //     parseInt(partner_user_id),
    //     parseInt(item_code),
    //     parseInt(partner_order_id),
    //     parseInt(total_amount),
    //     response.data.tid,
    //     "pending",
    //   ]
    // );

    res.json({
      next_redirect_pc_url: response.data.next_redirect_pc_url,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/api/payment/approval", async (req, res) => {
  console.log("결제승인요청");
  const { pg_token, dealKey } = req.query;
  const cid = "TC0ONETIME";
  const partner_order_id = dealKey;

  try {
    const [results] = await db.query(
      "SELECT orderKey, tid, user_id FROM `order` WHERE dealKey = ?",
      [partner_order_id]
    );
    if (results.length === 0) {
      throw new Error("No matching order found");
    }
    const orderKey = results[0].orderKey;
    const tid = results[0].tid;
    const partner_user_id = results[0].user_id;

    const response = await axios({
      url: "https://open-api.kakaopay.com/v1/payment/approve",
      method: "POST",
      headers: {
        Authorization: `SECRET_KEY ${SECRET_KEY}`,
        "Content-type": "application/json",
      },
      data: {
        cid,
        tid,
        partner_order_id,
        partner_user_id,
        pg_token,
      },
    });

    await db.query("UPDATE `order` SET orderStatus = ? WHERE dealKey = ?", [
      "completed",
      partner_order_id,
    ]);

    console.log(response.data);
    res.redirect(`/payment-success?orderKey=${orderKey}`);
  } catch (error) {
    console.error("Payment Approval Error:", error.response.data);
    res
      .status(500)
      .json({ success: false, message: "Payment approval failed." });
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
