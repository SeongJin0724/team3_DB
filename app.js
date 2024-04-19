require("dotenv").config();
var createError = require("http-errors");
var express = require("express");
var path = require("path");
const cors = require("cors");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
const nunjucks = require("nunjucks");
const bcrypt = require("bcrypt");
const PORT = process.env.PORT || 4000;
var indexRouter = require("./routes/index");
// var usersRouter = require('./routes/users');

var app = express();
const mysql = require("mysql2/promise");
const { log } = require("console");
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
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

// 회원가입 API
app.post("/api/signup", async (req, res) => {
  const { user_id, name, email, password, tel, dateJoined, address } = req.body;
  const hashedPassword = await bcrypt.hash(password, 8);

  const sql =
    "INSERT INTO user (user_id, name, email, password, tel, dateJoined, address) VALUES (?, ?, ?, ?, ?, ?, ?)";
  try {
    const result = await db.query(sql, [
      user_id,
      name,
      email,
      hashedPassword,
      tel,
      dateJoined,
      address,
    ]);
    res.send({ message: "User registered successfully!" });
  } catch (err) {
    console.error(err.message);
    res.status(500).send({ message: "Server error" });
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

app.get("/api/searchres", async (req, res) => {
  const searchTerm = req.query.aaa;
  if (!searchTerm) {
    return res.status(400).send({ error: "검색어를 입력해주세요." });
  }
  try {
    // 기존 코드에서는 [data, fields]를 사용했지만, 이는 특정 라이브러리나 ORM에서 반환 형식에 따른 것입니다.
    // 여기서는 가장 일반적인 형태로 수정합니다.
    const data = await db.query("SELECT * FROM item ", [`%${searchTerm}%`]);
    // 에러를 던지기 전에 발생하는 것을 확인하는 구문이 없어져야 합니다.
    // if (err) throw err; // 이 줄은 필요 없으며, 잘못된 사용 예입니다.
    res.json(data);
  } catch (err) {
    console.log(err);
    res.status(500).send({ message: "An error occurred" });
  }
});
// 검색
// app.get("/api/searchres", (req, res) => {
//   const searchTerm = req.query.term;

//   if (!searchTerm) {
//     return res.status(400).send({ error: "검색어를 입력해주세요." });
//   }
//   let query = `SELECT * FROM item
//   WHERE title LIKE '%${searchTerm}%' OR
//    category LIKE '%${searchTerm}%' OR
//    subCategory LIKE '%${searchTerm}%' OR
//   brand LIKE '%${searchTerm}%'`;

//   db.query(query, (err, results) => {
//     if (err) throw err;
//     res.json(results);
//   });
// });

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
