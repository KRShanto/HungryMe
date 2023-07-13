import bcrypt from "bcrypt";
import { NextAuthOptions } from "next-auth";
import { MongoDBAdapter } from "@next-auth/mongodb-adapter";
import GoogleProvider from "next-auth/providers/google";
import CredentialsProvider from "next-auth/providers/credentials";
// @ts-ignore
import clientPromise from "./clientPromise";
import User from "@/models/user";
import dbConnect from "@/lib/dbConnect";

export const authOptions: NextAuthOptions = {
  secret: process.env.SECRET!,
  // @ts-ignore
  adapter: MongoDBAdapter(clientPromise),
  session: {
    strategy: "jwt",
  },
  theme: {
    colorScheme: "dark",
  },
  providers: [
    CredentialsProvider({
      name: "HungryMe",
      credentials: {
        name: {
          label: "Your name",
          type: "text",
        },
        email: {
          label: "Your Email",
          type: "email",
        },
        password: {
          label: "Your Password",
          type: "password",
        },
      },
      async authorize(credentials) {
        // Login the user.
        // Check if the user's password match with the hased password saved in the database or not
        const { email, password } = credentials!;

        await dbConnect();

        const user = await User.findOne({ email });

        if (!user) {
          console.log("User not found");
          return null;
        }

        const isPasswordMatched = await bcrypt.compare(
          password,
          user.password!
        );

        if (!isPasswordMatched) {
          return null;
        }

        return {
          id: user.id,
          name: user.name,
          email: user.email,
          image: user.image,
        };
      },
    }),
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    }),
  ],
  callbacks: {
    async session({ session, token }) {
      if (token) {
        // @ts-ignore
        session.user.id = token.id;
        // @ts-ignore
        session.user.name = token.name;
        // @ts-ignore
        session.user.email = token.email;
        // @ts-ignore
        session.user.image = token.image;
      }

      return session;
    },

    async jwt({ token, user }) {
      return {
        id: user?.id,
        name: user?.name,
        email: user?.email,
        image: user?.image,
      };
    },
  },
};
