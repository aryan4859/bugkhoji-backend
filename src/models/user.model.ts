import mongoose, { Schema, Document } from 'mongoose';

export type UserRole = 'researcher' | 'admin';

export interface IUser extends Document {
    username: string; // unique key
    fullName: string;
    email: string;
    password: string;
    role: UserRole;
}

const UserSchema: Schema = new Schema<IUser>({
    username: { type: String, required: true, unique: true, trim: true },
    fullName: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['researcher', 'admin'], required: true }
}, {
    timestamps: true
});

export default mongoose.model<IUser>('User', UserSchema);