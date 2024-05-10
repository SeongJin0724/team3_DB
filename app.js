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

const saltRounds = 10;

// 미들웨어: 토큰 인증
async function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1];

  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.sendStatus(403);
  }
}

// 이메일 인증 코드 전송
app.post("/send-verification-code", async (req, res) => {
  const { email } = req.body;
  const verificationCode = Math.floor(1000 + Math.random() * 9000);
  const codeExpires = new Date(Date.now() + 3 * 60 * 1000)
    .toISOString()
    .slice(0, 19)
    .replace("T", " ");

  await db.query(
    `INSERT INTO user (email, verification_code, code_expires_at) VALUES (?, ?, ?)`,
    [email, verificationCode, codeExpires]
  );

  await transporter.sendMail({
    from: process.env.EMAIL_USERNAME,
    to: email,
    subject: "이메일 인증 코드",
    text: `이메일 인증코드: ${verificationCode}`,
  });

  res.send("Verification code sent.");
});

// 이메일 코드 검증
app.post("/verify-code", async (req, res) => {
  const { email, verificationCode } = req.body;
  const now = new Date().toISOString().slice(0, 19).replace("T", " ");

  const [user] = await db.query(
    `SELECT user_id FROM user WHERE email = ? AND verification_code = ? AND code_expires_at > ?`,
    [email, verificationCode, now]
  );

  if (user.length === 0)
    return res.status(400).send("Invalid or expired verification code.");

  await db.query(`UPDATE user SET email_verified = TRUE WHERE user_id = ?`, [
    user[0].user_id,
  ]);

  res.send("Email verified successfully.");
});

// 회원가입
app.post("/register", async (req, res) => {
  const { email, password, name, tel, address } = req.body;

  const [user] = await db.query(
    `SELECT user_id, email_verified FROM user WHERE email = ?`,
    [email]
  );
  if (user.length === 0 || !user[0].email_verified)
    return res
      .status(404)
      .send("사용자를 찾을 수 없거나 이메일 인증이 필요합니다.");

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await db.query(
    `UPDATE user SET password = ?, name = ?, tel = ?, address = ? WHERE user_id = ? AND email_verified = 1`,
    [hashedPassword, name, tel, address, user[0].user_id]
  );

  res.send("회원가입이 완료되었습니다.");
});

// 로그인
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const [users] = await db.query("SELECT * FROM user WHERE email = ?", [email]);

  if (users.length > 0 && (await bcrypt.compare(password, users[0].password))) {
    const { password, verification_code, code_expires_at, ...userInfo } =
      users[0];
    const token = jwt.sign({ userData: userInfo }, process.env.JWT_SECRET, {
      expiresIn: "4h",
    });

    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "strict",
      secure: true,
      maxAge: 4 * 60 * 60 * 1000,
    });
    res.send({ message: "Logged in successfully!", token });
  } else {
    res.status(401).send({ message: "Invalid email or password" });
  }
});

// 로그아웃
app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.send({ message: "Logged out successfully!" });
});

// 유저 조회
app.get("/api/user", authenticateToken, async (req, res) => {
  const userId = req.user.userData.user_id;
  const [users] = await db.query("SELECT * FROM user WHERE user_id = ?", [
    userId,
  ]);

  if (users.length > 0) {
    res.json({ user: users[0] });
  } else {
    res.status(404).send({ message: "User not found" });
  }
});
// 유저 업데이트
app.post("/api/updateUser", authenticateToken, async (req, res) => {
  // 토큰에서 사용자의 id를 추출합니다.
  const userId = req.user.userData.user_id;
  const updatedUserInfo = req.body;

  // 업데이트할 정보를 데이터베이스에 적용합니다.
  try {
    await db.query(
      `UPDATE user SET name = ?, tel = ?, address = ? WHERE user_id = ?`,
      [
        updatedUserInfo.email,
        updatedUserInfo.name,
        updatedUserInfo.password,
        updatedUserInfo.tel,
        updatedUserInfo.address,
        updatedUserInfo.bankName,
        updatedUserInfo.accountNum,
        updatedUserInfo.accountOwner,
        userId,
      ]
    );

    // 업데이트된 사용자 정보를 다시 조회합니다.
    const [users] = await db.query("SELECT * FROM user WHERE user_id = ?", [
      userId,
    ]);

    if (users.length > 0) {
      // 새 토큰을 생성합니다. 필요시 여기서 유효 시간을 조정할 수 있습니다.
      const { password, verification_code, code_expires_at, ...userInfo } =
        users[0];
      const newToken = jwt.sign(
        { userData: userInfo },
        process.env.JWT_SECRET,
        { expiresIn: "4h" }
      );

      // 업데이트된 사용자 정보와 새 토큰을 응답으로 보냅니다.
      res.json({ user: userInfo, newToken });
    } else {
      res.status(404).send({ message: "User not found after update" });
    }
  } catch (error) {
    console.error("Updating user info failed.", error);
    res.status(500).send({ message: "Internal server error" });
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
app.put("/api/infochange", async (req, res) => {
  const { email, password, tel, user_id } = req.body;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  try {
    const data = await db.query(
      `UPDATE user SET email = ?, password = ?, tel = ? WHERE user_id = ?`,
      [email, hashedPassword, tel, user_id]
    );
    res.json({ message: "회원정보가 수정되었습니다.", data });
  } catch (err) {
    console.error("Error", err);
    res.status(500).send({ error: "서버에러" });
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

// 포스트
app.get("/api/styleItem/:reviewKey", async (req, res) => {
  try {
    const { reviewKey } = req.params;
    const [data] = await db.query(
      `SELECT r.*, i.* 
      FROM reviews r
      JOIN item i ON r.itemKey = i.itemKey 
      WHERE r.reviewKey = ?`,
      [reviewKey]
    );

    if (data.length > 0) {
      res.json(data[0]);
    } else {
      res.status(404).send("Item not found");
    }
  } catch (err) {
    console.error(err);
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

// 계좌 정보 업데이트

app.post("/api/mypage/account", async (req, res) => {
  const { user_id, bankName, accountNum, accountOwner } = req.body;

  try {
    const data = await db.query(
      `UPDATE user SET bankName = ?, accountNum = ?, accountOwner = ? WHERE user_id = ?`,
      [bankName, accountNum, accountOwner, user_id] // 파라미터 순서 수정
    );
    res.json({ message: "계좌 변경이 완료되었습니다.", data });
  } catch (err) {
    console.error("Error:", err);
    // 서버 에러 응답
    res.status(500).send({ error: "서버 에러" });
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
    res.status(500).json({ message: "서버 에러 발생" });
  }
});

//주문 - 판매
app.post("/api/sendOrdersell", async (req, res) => {
  try {
    const { user_id, itemKey, dealKey, price } = req.body;
    const query =
      "INSERT INTO `order` (user_id, itemKey, dealKey, price) VALUES (?, ?, ?, ?)";
    await db.query(query, [user_id, itemKey, dealKey, price]);
    res.json({ message: "판매완료" });
  } catch (err) {
    res.status(500).json({ message: "서버 에러 발생" });
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
    item_code,
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
        approval_url: `http://127.0.0.1:3000/payment/approval?dealKey=${partner_order_id}`,
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

    await db.query(
      "INSERT INTO `order` (user_id, itemKey, dealKey, price, tid, orderStatus) VALUES (?, ?, ?, ?, ?, ?)",
      [
        parseInt(partner_user_id),
        parseInt(item_code),
        parseInt(partner_order_id),
        parseInt(total_amount),
        response.data.tid,
        "pending",
      ]
    );

    res.json({
      next_redirect_pc_url: response.data.next_redirect_pc_url,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "서버 에러 발생" });
  }
});

app.get("/api/payment/approval", async (req, res) => {
  const { dealKey, pg_token } = req.query;
  const cid = "TC0ONETIME";
  const partner_order_id = dealKey;

  try {
    const results = await db.query(
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
