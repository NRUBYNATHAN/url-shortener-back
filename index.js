import express from "express";
import { MongoClient } from "mongodb";

import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { ObjectId } from "mongodb";
// var nodemailer = require("nodemailer");
import nodemailer from "nodemailer";
// import { auth } from "./middleware/auth.js";
// import shortUrl from "shortUrl";
import * as dotenv from "dotenv";
dotenv.config();

const app = express();

const PORT = process.env.PORT;

const MONGO_URL = process.env.MONGO_URL;

const client = new MongoClient(MONGO_URL); // dial
// Top level await
await client.connect(); // call
console.log("Mongo is connected !!!  ");
app.use(cors());

async function genrateHashedPassword(password) {
  const NO_OF_ROUNDS = 10;
  const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
  const HashedPassword = await bcrypt.hash(password, salt);
  return HashedPassword;
}
app.get("/", function (request, response) {
  response.send("🎊✨🤩");
});

app.post("/signup", express.json(), async function (request, response) {
  const { firstname, lastname, email, password } = request.body;
  const userfromdb = await client
    .db("url")
    .collection("signup")
    .findOne({ email: email });
  if (userfromdb) {
    response.status(400).send({ message: "user already exists" });
  } else {
    const HashedPassword = await genrateHashedPassword(password);
    const result = await client.db("url").collection("signup").insertOne({
      firstname: firstname,
      lastname: lastname,
      email: email,
      password: HashedPassword,
    });
    response.send(result);
    console.log(result);
  }
});

app.post("/login", express.json(), async function (request, response) {
  const { email, password } = request.body;
  const userfromdb = await client
    .db("url")
    .collection("signup")
    .findOne({ email: email });

  if (!userfromdb) {
    response.status(400).send({ message: "invalid credentials" });
  } else {
    const storedpassword = userfromdb.password;
    const isPasswordCheck = await bcrypt.compare(password, storedpassword);
    console.log(isPasswordCheck);
    if (isPasswordCheck) {
      const token = jwt.sign({ id: userfromdb._id }, process.env.SECRET);
      response.send({ message: "successfully login", token: token });
    } else {
      response.status(400).send({ message: "invalid credentials" });
    }
  }
});

app.post("/forgot", express.json(), async function (request, response) {
  const { email } = request.body;
  try {
    const userfromdb = await client
      .db("url")
      .collection("signup")
      .findOne({ email: email });

    if (!userfromdb) {
      response.json({ status: "user not exists pls signup" });
    }
    const secret = process.env.SECRET + userfromdb.password;
    const token = jwt.sign(
      { email: userfromdb.email, id: userfromdb._id },
      secret,
      { expiresIn: "5m" }
    );
    const link = `http://localhost:5173/reset?id=${userfromdb._id}&token=${token}`;

    // create reusable transporter object using the default SMTP transport
    let transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "rubynathan999@gmail.com",
        pass: "biknetgulezybmjc",
      },
    });

    // setup email data with unicode symbols
    let mailOptions = {
      from: "rubynathan999@gmail.com", // sender address
      to: userfromdb.email, // list of receivers
      subject: "forgot password reset flow using nodejs and nodemailer", // Subject line
      // plain text body
      html: `<a href=${link}>click here</a>`,
    };

    // send mail with defined transport object
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return console.log(error);
      }
      console.log("Message sent: %s", info.messageId);
      response.status(200).json();
    });

    // console.log(link);
  } catch (error) {}
});

app.post(
  "/reset/:id/:token",
  express.json(),
  async function (request, response) {
    const { id, token } = request.params;
    const { password } = request.body;
    const userfromdb = await client
      .db("url")
      .collection("signup")
      .findOne({ _id: new ObjectId(id) });

    if (!userfromdb) {
      response.send({ message: "user not exists" });
    }
    const secret = process.env.SECRET + userfromdb.password;
    try {
      // const verify = jwt.verify(token, secret);

      const HashedPassword = await genrateHashedPassword(password);
      const result = await client
        .db("url")
        .collection("signup")

        .updateOne(
          {
            password: userfromdb.password,
          },
          {
            $set: {
              password: HashedPassword,
            },
          }
        );
      response.send({ message: "password updated" });
      console.log(result);
    } catch (error) {
      console.log(error);
      response.send({ message: "not verified" });
    }
  }
);

app.listen(PORT, () => console.log(`The server started in: ${PORT} ✨✨`));
