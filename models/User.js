import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema(
	{
		login: { 'type': String },
		firstName: { 'type': String },
		lastName: { 'type': String },
		email: { 'type': String },
		hash: { 'type': String },
		accessGroups: { 'type': String },
	},
	{
		timestamps: true,
		versionKey: false,
		collection: 'users'
	});

const UserModel = mongoose.model('UserModel', UserSchema);

export default UserModel;