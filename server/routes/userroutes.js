const express = require("express");
const bcrypt = require("bcrypt");
const { getUser, setUser } = require('../session.js');

const { findOneUser, findAllUsers, addAUser, updateUser, removeUser, findByUsername  } = require("../controllers/userController.js");

const router = express.Router();

router.get("/:id", async (req, res, next) => {
    let { id } = req.params;
    let data;
    if (id) {
        data = await findOneUser(id);
        res.json(data);
    } else {
        data = await findAllUsers();
        res.json(data);
    }
});

router.post("/signup", async (req, res, next) => {
  try {
    // Check if the user already exists by username
    const existingUser = await findByUsername(req.body.userName);
    if (existingUser) {
      // If the user already exists, send a 409 Conflict status and a relevant message
      console.warn(
        `Duplicate user attempt: ${req.body.userName} already exists.`
      );
      return res.status(409).json({ message: "Username already exists" });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10); // Larger number = more secure
    const hashed = await bcrypt.hash(req.body.password, salt);

    let userData = req.body;
    userData.hashedPassword = hashed;
    delete userData.password;

    let data = await addAUser(userData);
    res.status(201).json(data);
  } catch (error) {
    console.error("Error during signup:", error);
    res.status(500).json({ message: "Internal server error", error });
  }
});

router.put("/:id", async (req, res, next) => {
    const { id } = req.params;
    let updatedData = req.body;
    const data = await updateUser(id, updatedData);
    res.json(data);
});

router.delete("/:id", async (req, res, next) => {
    let { id } = req.params;
    let data = await removeUser(id);
    res.json(data);
});
// Login user
router.post("/login", async (req, res) => {
    const findUser = await findByUsername(req.body.usernames);
    if (!findUser) {
        return res.status(400).send("Invalid username, double-check spelling.");
    }

    try {
        // Compare the plain text password with the hashed password from the database
        bcrypt.compare(req.body.passwords, findUser.passwords, function (err, result) {
            if (result) {
                setUser(findUser);
                res.json({ success: true, message: "login successful!" });
            } else {
                console.error(err);
                res.json({ success: false, message: "Invalid password" });
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Internal Server Error!" });
    }
});

module.exports = router;
