import { getServerSession } from "next-auth";
import { authOptions } from "../auth/[...nextauth]/options";
import dbConnect from "@/lib/dbConnect";
import UserModel from "@/models/User";
import { User } from "next-auth";

export async function POST(request: Request) {
  await dbConnect();

  const session = await getServerSession(authOptions);
  const user: User = session?.user;

  //check session and user available
  if (!session || !session.user) {
    return Response.json(
      {
        success: false,
        message: "Not Authenticated",
      },
      { status: 401 }
    );
  }

  const userId = user._id;

  //accept toggle msg flag from frontend
  const { acceptMessages } = await request.json();

  try {
    const updatedUser = await UserModel.findByIdAndUpdate(
      userId,
      {
        isAcceptingMessages: acceptMessages,
      },
      { new: true }
    );

    if (!updatedUser) {
      return Response.json(
        {
          success: false,
          message: "failed to update userstatus: accept message",
        },
        { status: 401 }
      );
    } else {
      return Response.json(
        {
          success: true,
          message: "Message acceptance status updated successfully",
          updatedUser,
        },
        { status: 200 }
      );
    }
  } catch (error) {
    console.log("failed to update userstatus: accept message", error);
    return Response.json(
      {
        success: false,
        message: "failed to update userstatus: accept message",
      },
      { status: 500 }
    );
  }
}
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export async function GET(request: Request) {
  await dbConnect();

  const session = await getServerSession(authOptions);
  const user: User = session?.user;

  //check session and user available
  if (!session || !session.user) {
    return Response.json(
      {
        success: false,
        message: "Not Authenticated",
      },
      { status: 401 }
    );
  }

  const userId = user._id;

  try {
    const foundUser = await UserModel.findById(userId);
    if (!foundUser) {
      return Response.json(
        {
          success: false,
          message: "User not found",
        },
        { status: 404 }
      );
    } else {
      return Response.json(
        {
          success: true,
          isAcceptingMessages: foundUser.isAcceptingMessages, //check model
        },
        { status: 200 }
      );
    }
  } catch (error) {
    console.log("failed to update userstatus: accept message", error);
    return Response.json(
      {
        success: false,
        message: "Error in getting message acceptance",
      },
      { status: 500 }
    );
  }
}
