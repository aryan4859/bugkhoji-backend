export type UserRole = 'researcher' | 'admin';

export interface IUserInput {
    username: string;
    fullName: string;
    email: string;
    password: string;
    role: UserRole;
}

export interface IUserOutput {
    id: string;
    username: string;
    fullName: string;
    email: string;
    role: UserRole;
    createdAt: Date;
    updatedAt: Date;
}

export interface IUserUpdate {
    username?: string;
    fullName?: string;
    email?: string;
    password?: string;
    role?: UserRole;
}