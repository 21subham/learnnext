import { getServerSession } from "next-auth";
import { authOptions } from "../../auth/[...nextauth]/options";
import dbConnect from "@/lib/dbConnect";
import UserModel from "@/models/User";
import { User } from "next-auth";

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ messageid: string }> } // Type for the params object
) {
  const { messageid } = await params;
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

  try {
    const updateResult = await UserModel.updateOne(
      { _id: user._id },
      { $pull: { messages: { _id: messageid } } }
    );

    if (updateResult.modifiedCount === 0) {
      return Response.json(
        {
          success: false,
          message: "Message not found or already deleted",
        },
        { status: 404 }
      );
    } else {
      return Response.json(
        {
          success: true,
          message: "Message  deleted",
        },
        { status: 200 }
      );
    }
  } catch (error) {
    console.log("Error deleting message:", error);

    return Response.json(
      {
        success: false,
        message: "Error deleting message",
      },
      { status: 500 }
    );
  }
}
