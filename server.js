import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import cors from 'cors';
import mongoose from "mongoose";
import UserModel from "./models/User.js";
import bcrypt from 'bcrypt';

dotenv.config();

mongoose.connect(process.env.MONGODB_URI);

const app = express();
const PORT = 3003;

app.use(cookieParser());
app.use(cors(
	{
		origin: 'http://localhost:3000',
		credentials: true
	}
));

app.use(express.json());
app.use(
	session({
		resave: true,
		saveUninitialized: true,
		secret: process.env.SESSION_SECRET || "use-env-secret728272"
	})
);

const userIsInGroup = (user, accessGroup) => {
	const accessGroupArray = user.accessGroups.split(',').map(m => m.trim());
	return accessGroupArray.includes(accessGroup);
}

app.post("/login", async (req, res) => {
	const login = req.body.login;
	// const password = req.body.password;
	let user = await UserModel.findOne({ login });
	if (!user) {
		user = await UserModel.findOne({ login: "anonymousUser" });
	}
	req.session.user = user;
	req.session.save();
	res.json(user);
});

app.post("/signup", async (req, res) => {
	const frontUser = req.body.user;
	if (frontUser.login.trim() === '' || frontUser.password1.trim() === '' || (frontUser.password1 !== frontUser.password2)) {
		res.sendStatus(403);
	} else {
		const salt = await bcrypt.genSalt();
		const hash = await bcrypt.hash(frontUser.password1, salt);
		const dbuser = await UserModel.create(
			{
				login: frontUser.login,
				firstName: frontUser.firstName,
				lastName: frontUser.lastName,
				email: frontUser.email,
				hash,
				accessGroups: 'loggedInUsers,notYetApprovedUsers'
			}
		);
		req.session.user = dbuser;
		req.session.save();
		res.json(dbuser);
	}
});

app.get("/currentuser", async (req, res) => {
	let user = req.session.user;
	if (!user) {
		user = await UserModel.findOne({ login: "anonymousUser" });
	}
	res.json({
		user
	});
});

app.post("/approveuser", async (req, res) => {
	const id = req.body.id;
	let user = req.session.user;
	if (!user) {
		res.sendStatus(403);
	} else {
		if (!userIsInGroup(user, 'admins')) {
			res.sendStatus(403);
		} else {
			const updateResult = await UserModel.findOneAndUpdate({ _id: new mongoose.Types.ObjectId(id) }, { $set: { accessGroups: 'loggedInUsers,members' } }, { new: true });
			res.json({
				result: updateResult
			});
		}
	}
});

app.get("/notyetapprovedusers", async (req, res) => {
	const users = await UserModel.find({ "accessGroups": { "$regex": "notYetApprovedUsers", "$options": "i" } });
	res.json({
		users
	});
});

app.get("/logout", async (req, res) => {
	req.session.destroy();
	const user = await UserModel.findOne({ login: "anonymousUser" });
	res.json(user);
});

app.listen(PORT, (req, res) => {
	console.log(`API listening on port http://localhost:${PORT}`);
});
