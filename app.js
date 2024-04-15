require("dotenv").config();
var createError = require("http-errors");
var express = require("express");
var path = require("path");
const cors = require("cors");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
const nunjucks = require("nunjucks");
const PORT = 4000;
var indexRouter = require("./routes/index");
// var usersRouter = require('./routes/users');

var app = express();
let mariadb = require("mariadb");
const db = mariadb.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

app.use(
  cors({
    origin: "*",
    credentials: true,
    optionsSuccessStatus: 200,
  })
);
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

app.listen(PORT, () => {
  console.log(`Server On : http://localhost:${PORT}`);
});

// 회원가입 API
app.post("/api/signup", async (req, res) => {
  const { user_id, name, email, password, tel, dateJoined, address } = req.body;
  const hashedPassword = await bcrypt.hash(password, 8);

  const sql =
    "INSERT INTO user (user_id, name, email, password, tel, dateJoined, address) VALUES (?, ?, ?, ?, ?, ?, ?)";
  db.query(
    sql,
    [user_id, name, email, hashedPassword, tel, dateJoined, address],
    (err, result) => {
      if (err) throw err;
      res.send({ message: "User registered successfully!" });
    }
  );
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

module.exports = app;
