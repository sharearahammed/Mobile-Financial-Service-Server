const express = require("express");
const app = express();
require("dotenv").config();
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const port = process.env.PORT || 5000;
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

// middleware
const corsOptions = {
  origin: [
    "http://localhost:5173",
    "http://localhost:5174",
    "https://mega-earning.netlify.app",
  ],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));

app.use(express.json());
app.use(cookieParser());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.netgysa.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();
    const secret = process.env.ACCESS_TOKEN_SECRET;

    const db = client.db("mfs");
    const usersCollection = db.collection("users");
    const transactionsCollection = db.collection("transactions");

    // Middleware to verify JWT
    function verifyToken(req, res, next) {
      const token = req.headers["authorization"];
      if (!token)
        return res.status(403).send({ message: "No token provided." });
      jwt.verify(token, secret, (err, decoded) => {
        if (err)
          return res
            .status(500)
            .send({ message: "Failed to authenticate token." });
        req.userId = decoded.id;
        next();
      });
    }

    // Middleware to check if the user is admin
    async function verifyAdmin(req, res, next) {
      const user = await usersCollection.findOne({
        _id: new ObjectId(req.userId),
      });
      if (user && user.role === "admin") {
        next();
      } else {
        res.status(403).send({ message: "Access denied. Admins only." });
      }
    }

    // Hash PIN
    async function hashPin(pin) {
      const salt = await bcrypt.genSalt(10);
      return bcrypt.hash(pin, salt);
    }

    // Compare PIN
    async function comparePin(pin, hashedPin) {
      return bcrypt.compare(pin, hashedPin);
    }

    // Registration Endpoint
    app.post("/register", async (req, res) => {
      const { name, pin, mobileNumber, email, role } = req.body;

      // Check if mobile number or email already exists
      const existingUser = await usersCollection.findOne({
        $or: [{ mobileNumber }, { email }],
      });

      if (existingUser) {
        return res
          .status(400)
          .send({ message: "Mobile number or email already exists" });
      }

      const hashedPin = await hashPin(pin);
      const user = {
        name,
        pin: hashedPin,
        mobileNumber,
        email,
        role,
        status: "pending",
        balance: role === "agent" ? 10000 : 0, // Initial balance
      };

      usersCollection.insertOne(user, (err, result) => {
        if (err) return res.status(500).send(err);
        res.status(201).send({
          message: "User registered successfully",
          userId: result.insertedId,
        });
      });
    });

    // Login Endpoint
    app.post("/login", async (req, res) => {
      const { mobileOrEmail, pin } = req.body;
      const user = await usersCollection.findOne({
        $or: [{ mobileNumber: mobileOrEmail }, { email: mobileOrEmail }],
      });
      if (!user) return res.status(404).send({ message: "User not found" });
      const validPin = await bcrypt.compare(pin, user.pin);
      if (!validPin) return res.status(401).send({ message: "Invalid PIN" });
      const token = jwt.sign({ id: user._id }, secret, { expiresIn: "1h" });
      res.status(200).send({ message: "Login successful", token });
    });

    // Example protected route
    app.get("/profile", verifyToken, async (req, res) => {
      const user = await usersCollection.findOne({
        _id: new ObjectId(req.userId),
      });
      res.status(200).send({ user });
    });

    // get a user
    app.get("/users/:email", async (req, res) => {
      const email = req.params.email;
      const query = { email: email };
      const result = await usersCollection.findOne(query);
      res.send(result);
    });

    // Get all users (Admin only)
    app.get("/admin/users", verifyToken, verifyAdmin, async (req, res) => {
      const users = await usersCollection.find().toArray();
      res.status(200).send({ users });
    });

    // Approve user (Admin only)
    app.post("/admin/approve", verifyToken, verifyAdmin, async (req, res) => {
      const { userId } = req.body;

      try {
        // Fetch the user's role
        const user = await usersCollection.findOne({
          _id: new ObjectId(userId),
        });

        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        // Determine the balance based on the user's role
        let balance;
        if (user.role === "user") {
          balance = 40;
        } else if (user.role === "agent") {
          balance = 1000;
        } else {
          balance = 0; // default balance for other roles if needed
        }

        // Update the user's status and balance
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(userId) },
          { $set: { status: "active", balance } }
        );

        if (result.modifiedCount === 1) {
          res.status(200).send({ message: "User approved successfully" });
        } else {
          res.status(400).send({ message: "User approval failed" });
        }
      } catch (error) {
        console.error("Error approving user:", error);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // Send Money Endpoint
    app.post("/send-money", verifyToken, async (req, res) => {
      const { recipientId, amount, pin } = req.body;
      if (amount < 50)
        return res
          .status(400)
          .send({ message: "Minimum transaction amount is 50 Taka" });
      const user = await usersCollection.findOne({
        _id: new ObjectId(req.userId),
      });
      const validPin = await comparePin(pin, user.pin);
      if (!validPin) return res.status(401).send({ message: "Invalid PIN" });
      if (user.balance < amount)
        return res.status(400).send({ message: "Insufficient balance" });
      const fee = amount > 100 ? 5 : 0;
      const recipient = await usersCollection.findOne({
        mobileNumber: recipientId,
      });
      if (!recipient)
        return res.status(404).send({ message: "Recipient not found" });
      usersCollection.updateOne(
        { _id: new ObjectId(req.userId) },
        { $inc: { balance: -(amount + fee) } }
      );
      usersCollection.updateOne(
        { _id: recipient._id },
        { $inc: { balance: amount } }
      );
      res.status(200).send({ message: "Money sent successfully" });
    });

    // Cash-Out Endpoint
    app.post("/cash-out", verifyToken, async (req, res) => {
      const { agentId, amount, pin } = req.body;
      const user = await db
        .collection("users")
        .findOne({ _id: new ObjectId(req.userId) });
      const validPin = await comparePin(pin, user.pin);
      if (!validPin) return res.status(401).send({ message: "Invalid PIN" });
      if (user.balance < amount)
        return res.status(400).send({ message: "Insufficient balance" });
      const agent = await db
        .collection("users")
        .findOne({ mobileNumber: agentId, role: "agent" });
      if (!agent) return res.status(404).send({ message: "Agent not found" });
      const fee = amount * 0.015;
      db.collection("users").updateOne(
        { _id: new ObjectId(req.userId) },
        { $inc: { balance: -(amount + fee) } }
      );
      db.collection("users").updateOne(
        { _id: agent._id },
        { $inc: { balance: amount } }
      );
      res.status(200).send({ message: "Cash out successful" });
    });

    // Get Pending Cash-In Requests Endpoint
    app.get("/cash-in-requests", verifyToken, async (req, res) => {
      const agent = await db
        .collection("users")
        .findOne({ _id: new ObjectId(req.userId) });
      if (!agent || agent.role !== "agent")
        return res.status(403).send({ message: "Access denied" });

      const requests = await db
        .collection("cashInRequests")
        .find({ agentId: agent._id, status: "pending" })
        .toArray();
      res.status(200).send({ requests });
    });

    // Cash-In Request Endpoint
    app.post("/cash-in-request", verifyToken, async (req, res) => {
      const { agentMobile, amount, agent_email,agent_mobileNumber} = req.body;
      const user = await db
        .collection("users")
        .findOne({ _id: new ObjectId(req.userId) });
      const agent = await db
        .collection("users")
        .findOne({ mobileNumber: agentMobile, role: "agent" });
      if (!agent) return res.status(404).send({ message: "Agent not found" });
      const cashInRequest = {
        user_email:user.email,
        user_mobileNumber:user.mobileNumber,
        agent_email,
        agent_mobileNumber,
        userId: req.userId,
        agentId: agent._id,
        amount,
        status: "pending",
      };
      db.collection("cashInRequests").insertOne(
        cashInRequest,
        (err, result) => {
          if (err) return res.status(500).send(err);
          res.status(201).send({
            message: "Cash-in request created successfully",
            requestId: result.insertedId,
          });
        }
      );
    });

    // Approve Cash-In Request Endpoint
    app.post("/approve-cash-in", verifyToken, async (req, res) => {
      try {
        const { requestId,agent_email,agent_mobileNumber } = req.body;
        const agent = await db.collection("users").findOne({
          _id: new ObjectId(req.userId),
          role: "agent",
        });
        if (!agent) return res.status(403).send({ message: "Access denied" });

        const request = await db.collection("cashInRequests").findOne({
          _id: new ObjectId(requestId),
          agentId: agent._id,
        });
        if (!request)
          return res.status(404).send({ message: "Request not found" });

        if (agent.balance < request.amount) {
          return res.status(400).send({ message: "Insufficient balance" });
        }

        await db
          .collection("users")
          .updateOne(
            { _id: new ObjectId(request.userId) },
            { $inc: { balance: request.amount } }
          );
        await db
          .collection("users")
          .updateOne(
            { _id: agent._id },
            { $inc: { balance: -request.amount } }
          );
        await db
          .collection("cashInRequests")
          .updateOne(
            { _id: new ObjectId(requestId) },
            { $set: { status: "approved" } }
          );

          await db.collection("cashInRequests").findOne()
        // Insert the transaction into the transactions collection
        await db.collection("transactions").insertOne({
          agent_email,
          agent_mobileNumber,
          type: "cash-in",
          amount: request.amount,
          userId: request.userId,
          agentId: agent._id,
          timestamp: new Date(),
        });

        res
          .status(200)
          .send({ message: "Cash-in request approved successfully" });
      } catch (error) {
        console.error("Error approving cash-in request:", error);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // Balance Inquiry Endpoint
    app.get("/balance", verifyToken, async (req, res) => {
      const user = await db
        .collection("users")
        .findOne({ _id: new ObjectId(req.userId) });
      if (!user) return res.status(404).send({ message: "User not found" });
      res.status(200).send({ balance: user.balance });
    });

    // Transaction History Endpoint
    app.get("/user-transactions/:user_mobileNumber", verifyToken, async (req, res) => {
      const user_mobileNumber = req.params.user_mobileNumber;
      const query = {user_mobileNumber: user_mobileNumber};
      const transactions = await db
        .collection("transactions")
        .find(query)
        .sort({ date: -1 }) // Sort by date in descending order
        .limit(10) // Limit to the last 10 transactions
        .toArray();
      res.status(200).send({ transactions });
    });

    // Agent Transaction Management Endpoint
    app.post("/manage-transaction", verifyToken, async (req, res) => {
      const { requestId, action } = req.body;
      const agent = await usersCollection.findOne({
        _id: new ObjectId(req.userId),
        role: "agent",
      });
      if (!agent) return res.status(403).send({ message: "Access denied" });
      // Logic to handle transaction request (approve/decline)
      res.status(200).send({ message: "Transaction managed successfully" });
    });

    // User Management for Admin Endpoint
    app.get("/users", verifyToken, async (req, res) => {
      const admin = await usersCollection.findOne({
        _id: new ObjectId(req.userId),
        role: "admin",
      });
      if (!admin) return res.status(403).send({ message: "Access denied" });
      const users = await usersCollection.find({}).toArray();
      res.status(200).send({ users });
    });

    // System Monitoring for Admin Endpoint
    app.get("/system-transactions", verifyToken, async (req, res) => {
      const admin = await usersCollection.findOne({
        _id: new ObjectId(req.userId),
        role: "admin",
      });
      if (!admin) return res.status(403).send({ message: "Access denied" });
      const transactions = await transactionsCollection.find({}).toArray();
      res.status(200).send({ transactions });
    });

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello from mfs server..");
});

app.listen(port, () => {
  console.log(`MFS server is running on port ${port}`);
});
